"use client";

import { Children, Fragment, isValidElement, useId, useRef, useState } from "react";
import type { ComponentProps, ReactElement, ReactNode } from "react";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

type AppSelectOptionProps = {
	value: string | number;
	children: ReactNode;
	disabled?: boolean;
};

type AppSelectProps = Omit<
	ComponentProps<typeof SelectTrigger>,
	"value" | "defaultValue" | "children" | "onChange" | "ref"
> & {
	value?: string | number;
	defaultValue?: string | number;
	onValueChange?: (value: string) => void;
	children: ReactNode;
	name?: string;
	required?: boolean;
	contentClassName?: string;
};

// Encoding every option preserves blank filter values without reserving a user value.
const optionValue = (value: string | number) => `allauth-value:${value}`;

function options(children: ReactNode): ReactElement<AppSelectOptionProps>[] {
	return Children.toArray(children).flatMap((child) => {
		if (!isValidElement(child)) return [];
		if (child.type === Fragment)
			return options((child.props as { children?: ReactNode }).children);
		return child.type === AppSelectOption
			? [child as ReactElement<AppSelectOptionProps>]
			: [];
	});
}

/** Styled, keyboard-accessible selection for Console filters and forms. */
export function AppSelect({
	value,
	defaultValue,
	onValueChange,
	children,
	name,
	required,
	disabled,
	className,
	contentClassName,
	...triggerProps
}: AppSelectProps) {
	const items = options(children);
	const [localValue, setLocalValue] = useState(
		String(defaultValue ?? items.find((item) => !item.props.disabled)?.props.value ?? ""),
	);
	const [invalid, setInvalid] = useState(false);
	const trigger = useRef<HTMLButtonElement>(null);
	const errorId = useId();
	const selected = value === undefined ? localValue : String(value);
	const label = items.find((item) => String(item.props.value) === selected)?.props.children;
	const change = (next: string) => {
		setLocalValue(next);
		setInvalid(false);
		onValueChange?.(next);
	};
	return (
		<>
		<Select
			value={optionValue(selected)}
			onValueChange={(next) => change(next.slice("allauth-value:".length))}
			disabled={disabled}
		>
			<SelectTrigger
				{...triggerProps}
				ref={trigger}
				type="button"
				aria-required={required || undefined}
				aria-invalid={invalid || triggerProps["aria-invalid"]}
				aria-describedby={invalid ? [triggerProps["aria-describedby"], errorId].filter(Boolean).join(" ") : triggerProps["aria-describedby"]}
				className={cn("allauth-select-trigger w-auto gap-3", className)}
			>
				<SelectValue className="truncate text-left">{label}</SelectValue>
			</SelectTrigger>
			<SelectContent className={cn("allauth-select-content", contentClassName)}>
				{children}
			</SelectContent>
		</Select>
		{name || required ? (
			<select
				aria-hidden="true"
				tabIndex={-1}
				className="sr-only pointer-events-none"
				name={name}
				required={required}
				disabled={disabled}
				value={selected}
				onChange={(event) => change(event.target.value)}
				onInvalid={(event) => {
					event.preventDefault();
					setInvalid(true);
					trigger.current?.focus();
				}}
			>
				{items.map((item) => <option key={item.props.value} value={item.props.value} disabled={item.props.disabled}>{item.props.children}</option>)}
			</select>
		) : null}
		{invalid ? <span id={errorId} role="alert" className="text-xs text-destructive">Please select an option.</span> : null}
		</>
	);
}

/** An option in an AppSelect, including an empty value for an unfiltered choice. */
export function AppSelectOption({ value, children, disabled }: AppSelectOptionProps) {
	return (
		<SelectItem value={optionValue(value)} disabled={disabled}>
			{children}
		</SelectItem>
	);
}
