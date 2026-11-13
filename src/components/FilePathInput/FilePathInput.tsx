import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "@core/icons";
import SecretInput from "../SecretInput/SecretInput";
import Button from "../Button/Button";
import useToastState from "@core/states/toastState";
import { SecretRefsEditor } from "@core/helpers/secretRefs";

export type FilePathInputProps = {
  value: string,
  onValue: (value: string) => void,
  placeholder?: string,
  dialogTitle?: string,
  // The field's path in the saved item, for items that can take it from a secret.
  path?: string,
  refs?: SecretRefsEditor,
};

function FilePathInput(props: FilePathInputProps) {
  const { pushError } = useToastState;

  async function browse() {
    try {
      const picked = await open({ multiple: false, directory: false, title: props.dialogTitle });
      if (typeof picked === "string") props.onValue(picked);
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <SecretInput
      path={props.path ?? ""}
      refs={props.path ? props.refs : undefined}
      value={props.value}
      onValue={props.onValue}
      placeholder={props.placeholder}
      mono
      after={
        <Button icon size="sm" tooltip="Browse" onClick={browse}>
          <FolderOpen size={14} />
        </Button>
      }
    />
  );
}

export default FilePathInput;
