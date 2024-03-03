import ElectricCarIcon from "@mui/icons-material/ElectricCar";
import InsertChartIcon from "@mui/icons-material/InsertChart";
import Battery3BarIcon from "@mui/icons-material/Battery3Bar";
import DatasetIcon from "@mui/icons-material/Dataset";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import "./Sidebar.css";
import { useNavigate } from "react-router-dom";

interface IsideState {
  sideState: number;
  setSideState: (idx: number) => void;
}

export function Sidebar({ sideState, setSideState }: IsideState) {
  const navigate = useNavigate();
  const goBack = () => {
    navigate("/mypage");
  };

  const onClickHandler = (idx: number) => {
    setSideState(idx);
  };

  return (
    <div
      style={{
        backgroundColor: "#303030",
        position: "fixed",
        top: 0,
        left: 0,
        height: "100%",
        width: "10%",
        color: "#bbbbbb",
      }}
    >
      <div
        style={{
          padding: "25px 0px 0px 10px",
          marginBottom: "60px",
          display: "flex",
          alignItems: "center",
        }}
        className="back"
        onClick={goBack}
      >
        <ArrowBackIcon className="IconMargin" /> 뒤로가기
      </div>
      <div
        className={sideState === 1 ? "IconDiv selectedIcon" : "IconDiv"}
        onClick={() => onClickHandler(1)}
      >
        <ElectricCarIcon className="IconMargin" /> 차량 기본 정보
      </div>
      <div
        className={sideState === 2 ? "IconDiv selectedIcon" : "IconDiv"}
        onClick={() => onClickHandler(2)}
      >
        <InsertChartIcon className="IconMargin" /> 차량 상세 정보
      </div>
      <div
        className={sideState === 3 ? "IconDiv selectedIcon" : "IconDiv"}
        onClick={() => onClickHandler(3)}
      >
        <Battery3BarIcon className="IconMargin" /> 배터리팩 정보
      </div>
      <div
        className={sideState === 4 ? "IconDiv selectedIcon" : "IconDiv"}
        onClick={() => onClickHandler(4)}
      >
        <DatasetIcon className="IconMargin" /> 원시 데이터
      </div>
    </div>
  );
}
