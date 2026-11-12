import { AppSelect, AppSelectOption } from "./ui/app-select";
import { Button } from "./ui/button";

const sizes = [10, 20, 50];

export function HostedOrganizationPagination({
	label,
	page,
	pageCount,
	size,
	setPage,
	setSize,
}: {
	label: string;
	page: number;
	pageCount: number;
	size: number;
	setPage(page: number): void;
	setSize(size: number): void;
}) {
	return (
		<div className="flex flex-wrap items-center gap-2 text-sm">
			<span className="text-muted-foreground">
				Page {page + 1} of {pageCount}
			</span>
			<AppSelect
				aria-label={`${label} per page`}
				value={String(size)}
				onValueChange={(value) => setSize(Number(value))}
				className="rounded-md border px-2 text-sm"
			>
				{sizes.map((value) => (
					<AppSelectOption key={value} value={String(value)}>
						{value} per page
					</AppSelectOption>
				))}
			</AppSelect>
			<Button
				type="button"
				size="sm"
				variant="outline"
				disabled={page === 0}
				onClick={() => setPage(0)}
			>
				First
			</Button>
			<Button
				type="button"
				size="sm"
				variant="outline"
				disabled={page === 0}
				onClick={() => setPage(page - 1)}
			>
				Previous
			</Button>
			<Button
				type="button"
				size="sm"
				variant="outline"
				disabled={page + 1 >= pageCount}
				onClick={() => setPage(page + 1)}
			>
				Next
			</Button>
			<Button
				type="button"
				size="sm"
				variant="outline"
				disabled={page + 1 >= pageCount}
				onClick={() => setPage(pageCount - 1)}
			>
				Last
			</Button>
		</div>
	);
}
