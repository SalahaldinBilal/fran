import { ConnectionProfile } from "@core/types";
import { TileControls } from "@core/components/Tiling/TileLayout";

export type PanelProps = {
  controls: TileControls,
  search: string,
  onEditConnection: (profile: ConnectionProfile | null) => void,
};
