import Paper from "@mui/material/Paper";
import "./CarDetail.css";
import { ProgressBar } from "./ProgressBar";
import { CircularProgressbar } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";
import GradientSVG from "./GradientSVG";
import { styled } from "@mui/material/styles";
import Tooltip, { TooltipProps, tooltipClasses } from "@mui/material/Tooltip";
import { AnalysisInfo, SOHData, UserDetailInfo } from "../../interfaces";
import { UserInfoHeader } from "./UserInfoHeader";
import { TimeSoh } from "./Recharts/TimeSoh";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";

export function CarDetail({
  userDetailInfo,
  analysisInfo,
  SOHData,
  err,
}: {
  userDetailInfo: UserDetailInfo | null;
  analysisInfo: AnalysisInfo | null;
  SOHData: SOHData[] | null;
  err: number | null;
}) {
  const CustomWidthTooltip = styled(({ className, ...props }: TooltipProps) => (
    <Tooltip {...props} classes={{ popper: className }} />
  ))({
    [`& .${tooltipClasses.tooltip}`]: {
      maxWidth: 200,
    },
  });
  const LongWidthTooltip = styled(({ className, ...props }: TooltipProps) => (
    <Tooltip {...props} classes={{ popper: className }} />
  ))({
    [`& .${tooltipClasses.tooltip}`]: {
      maxWidth: 250,
    },
  });

  // 현재 시각
  const today = new Date();
  const endYear = today.getFullYear();
  const endMonth = ("0" + (today.getMonth() + 1)).slice(-2);
  const endDay = ("0" + today.getDate()).slice(-2);
  const hours = ("0" + today.getHours()).slice(-2);
  const minutes = ("0" + today.getMinutes()).slice(-2);
  const timeString = hours + ":" + minutes;
  const EndDateString = endYear + "-" + endMonth + "-" + endDay;

  return err ? (
    <div style={{ height: "85%" }}>
      <UserInfoHeader />
      <div style={{ color: "#bbbbbb", height: "20%", padding: "10px" }}>
        해당 차량의 BMS 데이터가 존재하지 않습니다.
      </div>
    </div>
  ) : (
    <div style={{ height: "85%" }}>
      <UserInfoHeader />
      <div
        style={{
          height: "43%",
          backgroundColor: "#282828",
          marginTop: "-1px",
          marginBottom: "15px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            paddingLeft: "24px",
            paddingTop: "10px",
            color: "#7f7f7f",
            fontWeight: "bold",
          }}
        >
          SOH 차트
          <Tooltip
            title={
              <div>
                <div>현재 시각 기준 ({EndDateString + " " + timeString})</div>
                <div>50 cycle 전까지의 SOH(배터리 성능 상태)를 나타냅니다.</div>
                <div>1 cycle : 충·방전 주기 1회</div>
              </div>
            }
            placement="right-start"
            arrow
          >
            <HelpOutlineIcon fontSize="small" style={{ marginLeft: "5px" }} />
          </Tooltip>
        </div>
        <TimeSoh SOHData={SOHData} />
      </div>
      <div
        style={{
          height: "35%",
          display: "flex",
          justifyContent: "space-between",
        }}
      >
        <Paper
          style={{
            width: "45%",
            height: "100%",
            backgroundColor: "#303030",
            display: "flex",
          }}
        >
          <div
            style={{
              width: "52%",
              height: "100%",
              fontWeight: "bold",
            }}
          >
            <div
              style={{
                padding: "16px 0px 24px 16px",
                color: "white",
              }}
            >
              충전 정보
            </div>
            <div
              style={{
                display: "flex",
                color: "#bbbbbb",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div style={{ display: "flex", flexDirection: "column" }}>
                <span className="batteryDataTitle">급속 충전 횟수</span>
                <span className="batteryDataTitle">완속 충전 횟수</span>
                <span className="batteryDataTitle">배터리 동작 시간</span>
                <span style={{ paddingLeft: "16px" }}>누적 사이클</span>
              </div>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "end",
                }}
              >
                <span className="batteryContent">
                  {analysisInfo?.fastCharge}회
                </span>
                <span className="batteryContent">
                  {analysisInfo?.slowCharge}회
                </span>
                <span className="batteryContent">
                  {(analysisInfo!.totalRuntime / 360).toFixed(2)}시간
                </span>
                <span style={{ paddingRight: "16px" }}>
                  {analysisInfo?.totalCycle}회
                </span>
              </div>
            </div>
          </div>
          <div style={{ width: "48%", height: "100%" }}>
            <CustomWidthTooltip
              title="충전량에 비해 방전량이 많이 감소했다면 누설전류를 의심해 볼 수 있습니다."
              placement="bottom"
              arrow
            >
              <div
                style={{
                  color: "white",
                  padding: "16px 0px 0px 30px",
                  fontWeight: "bold",
                  marginBottom: "24px",
                }}
              >
                누적 충전량 대비 누적 방전량
              </div>
            </CustomWidthTooltip>
            <div
              style={{
                paddingLeft: "30px",
                paddingBottom: "10px",
                color: "#bbbbbb",
                fontSize: "14px",
              }}
            >
              누적 충전량 : {analysisInfo?.totalCharge} kwh
            </div>
            <div
              style={{
                paddingLeft: "30px",
                paddingBottom: "10px",
                color: "#bbbbbb",
                fontSize: "14px",
                marginBottom: "16px",
              }}
            >
              누적 방전량 : {analysisInfo?.totalDischarge} kwh
            </div>
            <ProgressBar
              ratio={
                (analysisInfo!.totalDischarge / analysisInfo!.totalCharge) * 100
              }
            />
          </div>
        </Paper>
        <Paper
          style={{
            width: "25%",
            height: "100%",
            backgroundColor: "#303030",
          }}
        >
          <div
            style={{
              height: "50%",
              fontWeight: "bold",
            }}
          >
            <LongWidthTooltip
              title={
                <div style={{ padding: "3px" }}>
                  <div>
                    해당 데이터는 최근 충·방전 50 싸이클을 기반으로 예측한
                    데이터 입니다.
                  </div>
                  <div>차후 운전 변화로 충분히 변할 수 있습니다.</div>
                </div>
              }
              placement="bottom-start"
              arrow
            >
              <div
                style={{
                  margin: "16px 0px 18px 16px",
                  color: "white",
                  width: "fit-content",
                }}
              >
                배터리 교체 예정 시기
              </div>
            </LongWidthTooltip>
            <div
              style={{
                paddingLeft: "16px",
                color: "#bbbbbb",
                // fontSize: "18px",
              }}
            >
              <span>완충 기준으로 </span>
              {/* <span>{analysisInfo?.bLeftCycle}번 </span> */}
              <span style={{ fontSize: "18px" }}>
                {analysisInfo?.bleftCycle}번{" "}
              </span>
              <span>충전 이후</span>
            </div>
          </div>
          <div
            style={{
              height: "50%",
              fontWeight: "bold",
            }}
          >
            <LongWidthTooltip
              title="누적 방전량과 전비를 기반으로 산정했습니다."
              placement="bottom-start"
              arrow
            >
              <div
                style={{
                  margin: "10px 0px 18px 16px",
                  color: "white",
                  width: "fit-content",
                }}
              >
                예상 누적 주행거리
              </div>
            </LongWidthTooltip>
            <div
              style={{
                paddingLeft: "16px",
                color: "#bbbbbb",
                fontSize: "18px",
              }}
            >
              {analysisInfo?.totalDrive}km
            </div>
          </div>
        </Paper>
        <Paper
          style={{
            width: "25%",
            height: "100%",
            backgroundColor: "#303030",
          }}
        >
          <LongWidthTooltip
            title={
              <div style={{ padding: "3px" }}>
                <div>BMS기반 SoH(State Of Health)데이터 입니다.</div>
                <div>75% 미만으로 떨어질 시에는 교체를 권장합니다.</div>
              </div>
            }
            placement="bottom-start"
            arrow
          >
            <div
              style={{
                margin: "16px 0px 0px 16px",
                color: "white",
                fontWeight: "bold",
                width: "fit-content",
              }}
            >
              배터리 성능 상태
            </div>
          </LongWidthTooltip>

          <div
            style={{
              width: "48%",
              margin: "auto",
              position: "relative",
              marginTop: "-8px",
            }}
          >
            <div
              style={{
                position: "absolute",
                top: "45%",
                left: "25%",
                fontSize: "24px",
                fontWeight: "bold",
                color: "#bbbbbb",
              }}
            >
              {analysisInfo?.btotalScore}%
            </div>
            <GradientSVG />
            <CircularProgressbar
              value={analysisInfo!.btotalScore}
              // text={`${dummy.SOH}%`}/
              styles={{
                path: {
                  stroke: "url(#SOH)",
                  height: "100%",
                  strokeLinecap: "butt",
                },
                trail: {
                  stroke: "#bbbbbb",
                },
              }}
            />
          </div>
        </Paper>
      </div>
    </div>
  );
}
