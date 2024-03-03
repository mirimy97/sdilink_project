import { NowBMSData } from "../../interfaces";
import "./Hex.css";

export function Hex({ moduleData }: { moduleData: NowBMSData }) {
  const first = moduleData.cellLogList.slice(0, 4);
  const second = moduleData.cellLogList.slice(4, 8);
  const third = moduleData.cellLogList.slice(8, 12);

  return (
    <div className="hex-grid">
      <div className="moduleNum">{moduleData.moduleCode}</div>
      <div className="hex-row">
        {first.map((cell, i) => (
          <div
            className={
              cell.isNormal !== -1
                ? cell.isNormal === -10
                  ? "charging"
                  : "normal"
                : "outlier"
            }
            key={cell.id}
          >
            <div style={{ fontSize: "10px", textAlign: "center" }}>
              {cell.isNormal !== -1 ? "" : cell.voltageC.toFixed(2) + "V"}
            </div>
            <div style={{ fontSize: "10px", textAlign: "center" }}>
              {cell.isNormal !== -1 ? "" : cell.cellCode}
            </div>
          </div>
        ))}
      </div>
      <div className="hex-row middle">
        {second.map((cell, i) => (
          <div
            className={
              cell.isNormal !== -1
                ? cell.isNormal === -10
                  ? "charging"
                  : "normal"
                : "outlier"
            }
            key={cell.id}
          >
            <div style={{ fontSize: "10px", textAlign: "center" }}>
              {cell.isNormal !== -1 ? "" : cell.voltageC.toFixed(2) + "V"}
            </div>
            <div style={{ fontSize: "10px", textAlign: "center" }}>
              {cell.isNormal !== -1 ? "" : cell.cellCode}
            </div>
          </div>
        ))}
      </div>
      <div className="hex-row">
        {third.map((cell, i) => (
          <div
            className={
              cell.isNormal !== -1
                ? cell.isNormal === -10
                  ? "charging"
                  : "normal"
                : "outlier"
            }
            key={cell.id}
          >
            <div style={{ fontSize: "10px", textAlign: "center" }}>
              {cell.isNormal !== -1 ? "" : cell.voltageC.toFixed(2) + "V"}
            </div>
            <div style={{ fontSize: "10px", textAlign: "center" }}>
              {cell.isNormal !== -1 ? "" : cell.cellCode}
            </div>
          </div>
        ))}
      </div>
      <div className="moduleInfo">
        모듈 전압 : {moduleData.voltage.toFixed(2)}V &nbsp;&nbsp; 온도 :{" "}
        {moduleData.temp.toFixed(0)}℃
      </div>
    </div>
  );
}
