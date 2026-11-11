import { getTestInstance } from "better-auth/test";
import { admin } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
import { projectManagement } from "./management-plugin";

const origin = "http://localhost:3000";
const data = btoa(String.fromCharCode(255, 216, 255, 217));
async function fixture(available = true, ownership?: () => Promise<boolean>) {
 const upload = vi.fn(async (_asset: unknown, _userId: string) => "https://assets.allauth.co/branding/fixture/avatar.jpg");
 const instance = await getTestInstance({ trustedOrigins: [origin], plugins: [admin(), projectManagement({ projectId: "avatar-fixture", baseURL: origin, requirePlatformAdmin: async () => { throw new Error("Not a platform operation"); }, ...(available ? { uploadAvatar: upload } : {}), ...(ownership ? {avatarOwnershipAndDeletion: ownership} : {}) })] });
 const context = await instance.auth.$context;
 const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: instance.testUser.email }] });
 if (!user) throw new Error("Missing fixture user");
 await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
 const login = await instance.auth.api.signInEmail({ body: { email: instance.testUser.email, password: instance.testUser.password }, headers: new Headers({ origin }), asResponse: true });
 const cookie = login.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
 const call = (body: unknown = { contentType: "image/jpeg", data }, requestOrigin = origin, requestCookie = cookie) => instance.auth.handler(new Request(`${origin}/api/auth/sdk/avatar`, { method: "POST", headers: { origin: requestOrigin, cookie: requestCookie, "content-type": "application/json" }, body: JSON.stringify(body) }));
 return { instance, context, upload, user, call, cookie };
}
describe("native project profile photo upload", () => {
 it("advertises ownership separately and refuses selected owned uploads until the lifecycle gate is healthy", async () => {
  let ready = false; const f = await fixture(true, async () => ready);
  const config = async () => (await f.instance.auth.handler(new Request(`${origin}/api/auth/sdk/config`))).json();
  expect(await config()).toMatchObject({profileImageUpload:true,profileImageOwnershipAndDeletion:false});
  expect((await f.call()).status).toBe(503); expect(f.upload).not.toHaveBeenCalled();
  ready = true; expect(await config()).toMatchObject({profileImageOwnershipAndDeletion:true}); expect((await f.call()).status).toBe(200);
 });
 it("keeps legacy storage availability distinct from owned erasure capability", async () => {
  const f = await fixture(); const config = await f.instance.auth.handler(new Request(`${origin}/api/auth/sdk/config`));
  expect(await config.json()).toMatchObject({profileImageUpload:true,profileImageOwnershipAndDeletion:false});
 });

 it("uses only the fresh native identity and returns a draft URL without changing the profile", async () => {
  const f = await fixture(); const response = await f.call(); expect(response.status).toBe(200); expect(await response.json()).toEqual({ url: "https://assets.allauth.co/branding/fixture/avatar.jpg" });
  expect(f.upload).toHaveBeenCalledWith(expect.objectContaining({ contentType: "image/jpeg", extension: "jpg", bytes: new Uint8Array([255,216,255,217]) }), f.user.id);
  expect((await f.context.adapter.findOne<{ image?: string }>({ model: "user", where: [{ field: "id", value: f.user.id }] }))?.image).toBeFalsy();
  expect(response.headers.get("cache-control")).toBe("no-store");
 });
 it("fails closed for missing, unverified, banned, or cross-origin identities", async () => {
  const f = await fixture(); expect((await f.call(undefined, origin, "")).status).toBe(401);
  expect((await f.call(undefined, "https://evil.example")).status).toBe(403);
  for (const update of [{ emailVerified: false }, { emailVerified: true, banned: true }]) {
   await f.context.adapter.update({ model: "user", where: [{ field: "id", value: f.user.id }], update });
   expect((await f.call()).status).toBe(403);
  }
  expect(f.upload).not.toHaveBeenCalled();
 });
 it("rejects scope injection, invalid images, SVG, and oversized encoded photos", async () => {
  const f = await fixture();
  for (const body of [{ contentType: "image/jpeg", data, userId: "someone-else" }, { contentType: "image/png", data }, { contentType: "image/svg+xml", data: btoa("<svg/>") }, { contentType: "image/jpeg", data: "!!!!" }, { contentType: "image/jpeg", data: "A".repeat(180000) }]) expect((await f.call(body)).status).toBe(400);
  expect(f.upload).not.toHaveBeenCalled();
 });
 it("announces unavailable storage and fails without falling back to temporary uploads", async () => {
  const f = await fixture(false); const config = await f.instance.auth.handler(new Request(`${origin}/api/auth/sdk/config`)); expect(await config.json()).toMatchObject({ profileImageUpload: false }); expect((await f.call()).status).toBe(503);
 });
});
