import "./BasicInfo.css";
import { CarBasicInfo } from "../../interfaces";

export function BasicInfo({ basicInfo }: { basicInfo: CarBasicInfo | null }) {
  const imgSrc = `/assets/basicImg/${basicInfo?.id}.png`;
  const line_front = `/assets/lineImg/${basicInfo?.id}_front.png`;
  const line_side = `/assets/lineImg/${basicInfo?.id}_side.png`;
  const line_back = `/assets/lineImg/${basicInfo?.id}_back.png`;
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        height: "80%",
      }}
    >
      <div className="center" style={{ height: "50%" }}>
        <img src={imgSrc} alt={basicInfo?.modelName} />
      </div>
      <div className="center">
        <div className="carModel">
          {basicInfo?.maker} {basicInfo?.modelName}
        </div>
        <div className="carModel"></div>
        <div className="carModel"></div>
      </div>
      <div className="center">
        <div className="infoBox infoLine">
          연비 : {basicInfo?.efficiency}km/kWh
        </div>
        <div className="infoBox">정원 : {basicInfo?.peopleCapacity}명</div>
        <div className="infoBox infoLine">
          구동 방식 : {basicInfo?.drivingMethod}
        </div>
      </div>
      <div className="center">
        <div className="infoBox">배터리 종류 : {basicInfo?.batteryKind}</div>
        <div className="infoBox infoLine">
          배터리 용량 : {basicInfo?.batteryCapacity}Ah
        </div>
        <div className="infoBox">주행거리 : {basicInfo?.distance}km</div>
      </div>
      <div className="center">
        <img
          className="hatchback"
          src={line_front}
          alt="hatchback_front"
          width={200}
        />
        <img
          className="hatchback"
          src={line_side}
          alt="hatchback_side"
          width={380}
        />
        <img
          className="hatchback"
          src={line_back}
          alt="hatchback_back"
          width={200}
        />
      </div>
    </div>
  );
}
