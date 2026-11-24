import { App } from "antd";
import type { ModalFuncProps } from "antd";

type Confirmation = Omit<ModalFuncProps, "onOk"> & { onOk: () => Promise<boolean> };

export function useConfirmAction() {
  const { modal } = App.useApp();
  return ({ onOk, ...options }: Confirmation) => {
    const dialog = modal.confirm({
      icon: null,
      autoFocusButton: "cancel",
      ...options,
      onOk: async () => {
        if (!await onOk()) throw new Error("操作未完成");
      },
    });
    // Observe the hook modal so rejected confirmations stay open without an unhandled rejection.
    void dialog.then(() => undefined, () => undefined);
  };
}
