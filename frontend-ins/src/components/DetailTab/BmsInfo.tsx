import Tooltip from "@mui/material/Tooltip";
import { BMSChartData, NowBMSData } from "../../interfaces";
import { useAppSelector } from "../../redux/hooks";
import { Hex } from "./Hex";
import { PackInfoChart } from "./Recharts/PackInfoChart";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";

export function BmsInfo({
  nowBMSData,
  setNowBMSData,
  approvalId,
  accessToken,
  nowTime,
  setNowTime,
  bmsGraphData,
}: {
  nowBMSData: NowBMSData[] | null;
  setNowBMSData: (data: NowBMSData[]) => void;
  approvalId: string;
  accessToken: string;
  nowTime: string | null;
  setNowTime: (t: string) => void;
  bmsGraphData: BMSChartData[] | null;
}) {
  const packNum = useAppSelector((store) => store.detail.packCode);
  return nowBMSData ? (
    <div>
      <div
        style={{
          backgroundColor: "#303030",
          paddingTop: "10px",
          paddingBottom: "20px",
          paddingLeft: "16px",
          paddingRight: "16px",
        }}
      >
        <div
          style={{
            color: "#bbbbbb",
            marginBottom: "15px",
            fontWeight: "bold",
            display: "flex",
            alignItems: "center",
          }}
        >
          배터리팩 ({packNum}) 정보
          <span
            style={{ fontSize: "12px", color: "white", paddingLeft: "3px" }}
          >
            ({nowTime ? nowTime : ""})
          </span>
          <Tooltip
            title={
              <div>
                <div>이상치가 있는 셀은 붉게 나타납니다.</div>
                <div>충전 중일 때는 초록색으로 나타납니다.</div>
              </div>
            }
            placement="right"
            arrow
          >
            <HelpOutlineIcon
              style={{ marginLeft: "3px", fontSize: "16px", paddingTop: "2px" }}
            />
          </Tooltip>
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            marginBottom: "20px",
          }}
        >
          <Hex moduleData={nowBMSData[0]} />
          <Hex moduleData={nowBMSData[1]} />
          <Hex moduleData={nowBMSData[2]} />
          <Hex moduleData={nowBMSData[3]} />
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <Hex moduleData={nowBMSData[4]} />
          <Hex moduleData={nowBMSData[5]} />
          <Hex moduleData={nowBMSData[6]} />
          <Hex moduleData={nowBMSData[7]} />
        </div>
      </div>
      <div
        style={{
          height: "120%",
          backgroundColor: "#303030",
          marginTop: "15px",
          marginBottom: "15px",
          // borderRadius: "10px",
          width: "100%",
        }}
      >
        <PackInfoChart
          setNowBMSData={setNowBMSData}
          approvalId={approvalId}
          accessToken={accessToken}
          setNowTime={setNowTime}
          bmsGraphData={bmsGraphData}
        />
      </div>
    </div>
  ) : (
    <div style={{ color: "#bbbbbb", height: "20%", padding: "10px" }}>
      해당 차량의 BMS 데이터가 존재하지 않습니다.
    </div>
  );
}
