import { Tooltip } from "antd";
import type { TooltipProps } from "antd";
import { cloneElement, useEffect, useRef, useState } from "react";
import type { HTMLAttributes, ReactElement } from "react";

let tabbing = false;

export function useTooltipKeyboardNavigation() {
  useEffect(() => {
    let timer: number | undefined;
    function handleKey(event: KeyboardEvent) {
      if (event.key !== "Tab" || event.defaultPrevented) return;
      tabbing = true;
      window.clearTimeout(timer);
      timer = window.setTimeout(() => { tabbing = false; }, 0);
    }
    window.addEventListener("keydown", handleKey, true);
    return () => {
      window.removeEventListener("keydown", handleKey, true);
      window.clearTimeout(timer);
      tabbing = false;
    };
  }, []);
}

type TriggerEvents = Pick<HTMLAttributes<HTMLElement>,
  "onClickCapture" | "onFocus" | "onBlur" | "onPointerMove">;
type Props = Pick<TooltipProps, "title"> & {
  children: ReactElement<TriggerEvents>;
  clickToOpen?: boolean;
};

export default function DismissibleTooltip({ children, title, clickToOpen = false }: Props) {
  const [open, setOpen] = useState(false);
  const dismissed = useRef(false);

  function dismiss() {
    dismissed.current = true;
    setOpen(false);
  }

  useEffect(() => {
    if (!open) return;
    const listeners = new AbortController();
    const options = { capture: true, signal: listeners.signal };
    window.addEventListener("scroll", dismiss, options);
    window.addEventListener("blur", dismiss, options);
    window.addEventListener("hashchange", dismiss, options);
    if (!clickToOpen) window.addEventListener("pointerdown", dismiss, options);
    window.addEventListener("keydown", event => {
      if (event.key === "Escape") dismiss();
    }, options);
    return () => listeners.abort();
  }, [open, clickToOpen]);

  const trigger = clickToOpen ? children : cloneElement(children, {
    onClickCapture: event => {
      dismiss();
      children.props.onClickCapture?.(event);
    },
    onFocus: event => {
      // Dialogs restore focus to their opener. A new Tab press is intentional.
      if ((!dismissed.current || tabbing) && event.currentTarget.matches(":focus-visible")) setOpen(true);
      children.props.onFocus?.(event);
    },
    onBlur: event => {
      setOpen(false);
      children.props.onBlur?.(event);
    },
    onPointerMove: event => {
      if (dismissed.current && event.pointerType !== "touch" && (event.movementX || event.movementY)) {
        dismissed.current = false;
        setOpen(true);
      }
      children.props.onPointerMove?.(event);
    },
  });

  return <Tooltip title={title} trigger={clickToOpen ? "click" : "hover"}
    open={open} onOpenChange={next => {
      if (!next || clickToOpen || !dismissed.current) setOpen(next);
    }} destroyOnHidden styles={{ root: { pointerEvents: "none" } }}>
    {trigger}
  </Tooltip>;
}
