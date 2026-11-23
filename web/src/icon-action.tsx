import { Button, Tooltip } from "antd";
import type { ButtonProps } from "antd";
import type { Ref } from "react";

type IconActionProps = Omit<ButtonProps, "title" | "aria-label"> & {
  label: string;
  ref?: Ref<HTMLButtonElement | HTMLAnchorElement>;
};

export default function IconAction({ label, disabled, ...props }: IconActionProps) {
  const button = <Button type="text" size="small" {...props} disabled={disabled} aria-label={label} />;
  return (
    <Tooltip title={label} trigger={["hover", "focus"]} color="#25332e" destroyOnHidden>
      {disabled ? <span className="disabled-icon-action">{button}</span> : button}
    </Tooltip>
  );
}
