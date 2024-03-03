import { BmsTab } from "./BmsRaw/BmsTab";
import "./RawData.css";
import { ModuleCellsMapping, UserDetailInfo } from "../../interfaces";
import { UserInfoHeader } from "./UserInfoHeader";

export function RawData({
  userDetailInfo,
  moduleCellMapping,
  nowTime,
  err,
}: {
  userDetailInfo: UserDetailInfo | null;
  moduleCellMapping: ModuleCellsMapping | null;
  nowTime: string | null;
  err: number | null;
}) {
  return (
    <div style={{ height: "85%" }}>
      <UserInfoHeader />
      {err ? (
        <div style={{ color: "#bbbbbb", height: "20%", padding: "10px" }}>
          해당 차량의 BMS 데이터가 존재하지 않습니다.
        </div>
      ) : (
        <div style={{ height: "80%", marginTop: "-1px" }}>
          <BmsTab moduleCellMapping={moduleCellMapping} nowTime={nowTime} />
        </div>
      )}
    </div>
  );
}
