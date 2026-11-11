// Adapted from official shadcn/ui new-york-v4 registry (MIT). See ../ATTRIBUTION.md.
import { cn } from "cn";
import { Loader2Icon } from "lucide-react";

function Spinner({ className, ...props }: React.ComponentProps<"svg">) {
	return (
		<Loader2Icon
			role="status"
			aria-label="Loading"
			className={cn("size-4 animate-spin", className)}
			{...props}
		/>
	);
}

export { Spinner };
