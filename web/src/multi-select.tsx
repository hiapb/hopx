import { Select } from "antd";
import type { SelectProps } from "antd";
import type { BaseOptionType, DefaultOptionType } from "antd/es/select";
import { Check } from "lucide-react";

export default function MultiSelect<Value, Option extends BaseOptionType = DefaultOptionType>({
  mode = "multiple", ...props
}: SelectProps<Value, Option>) {
  return (
    <Select<Value, Option>
      {...props}
      mode={mode}
      classNames={{ popup: { root: "multi-select-popup" } }}
      menuItemSelectedIcon={({ isSelected }) => (
        <span className="multi-select-check" aria-hidden="true">
          {isSelected && <Check size={12} strokeWidth={2.6} />}
        </span>
      )}
    />
  );
}
