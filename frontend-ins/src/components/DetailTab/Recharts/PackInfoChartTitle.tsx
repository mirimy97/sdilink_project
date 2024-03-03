import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import Tooltip from "@mui/material/Tooltip";

export function PackInfoChartTitle() {
  const today = new Date();
  const endYear = today.getFullYear();
  const endMonth = ("0" + (today.getMonth() + 1)).slice(-2);
  const endDay = ("0" + today.getDate()).slice(-2);
  const hours = ("0" + today.getHours()).slice(-2);
  const minutes = ("0" + today.getMinutes()).slice(-2);
  const timeString = hours + ":" + minutes;
  const EndDateString = endYear + "-" + endMonth + "-" + endDay;

  return (
    <div
      style={{
        padding: "10px 0px 20px 20px",
        color: "#bbbbbb",
        fontWeight: "bold",
        display: "flex",
        alignItems: "center",
      }}
    >
      배터리 팩 전압, 전류, 온도 데이터
      <Tooltip
        title={
          <div>
            <div>현재 시각 기준 ({EndDateString + " " + timeString})</div>
            <div>3시간 전 주행거리까지의 데이터를 나타냅니다.</div>
          </div>
        }
        placement="right-start"
        arrow
      >
        <HelpOutlineIcon fontSize="small" style={{ marginLeft: "5px" }} />
      </Tooltip>
    </div>
  );
}
