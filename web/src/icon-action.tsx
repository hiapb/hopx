import { Button } from "antd";
import type { ButtonProps } from "antd";
import type { Ref } from "react";
import DismissibleTooltip from "./dismissible-tooltip";

type IconActionProps = Omit<ButtonProps, "title" | "aria-label"> & {
  label: string;
  ref?: Ref<HTMLButtonElement | HTMLAnchorElement>;
};

export default function IconAction({ label, disabled, ...props }: IconActionProps) {
  const button = <Button type="text" size="small" {...props} disabled={disabled} aria-label={label} />;
  return (
    <DismissibleTooltip title={label} color="#25332e">
      {disabled ? <span className="disabled-icon-action">{button}</span> : button}
    </DismissibleTooltip>
  );
}
