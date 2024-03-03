import { useAppDispatch, useAppSelector } from "../redux/hooks";
import LogoutIcon from "@mui/icons-material/Logout";
import { logoutIns } from "../redux/insurance";
import { useNavigate } from "react-router-dom";

export function Header() {
  // 로그인 시 redux 관리
  const info = useAppSelector((store) => store.insurance);
  // 로그아웃
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  return (
    <div style={{ paddingTop: "30px", color: "white", position: "relative" }}>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <div style={{ display: "flex" }}>
          <img
            src={
              info.name === "삼성화재" ? "/assets/samsung2.png" : info.imgSrc
            }
            alt={info.name}
            style={{
              width: "70px",
              height: "70px",
              borderRadius: "50px",
            }}
          />
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              marginLeft: "20px",
              lineHeight: "25px",
            }}
          >
            <div style={{ fontSize: "12px" }}>
              최근 접속 일시 : {info.loginDate}
            </div>
            <div style={{ fontWeight: "bold" }}>{info.name}</div>
          </div>
        </div>
      </div>
      <div
        onClick={() => {
          dispatch(logoutIns());
          navigate("/login");
        }}
      >
        <LogoutIcon
          style={{
            position: "absolute",
            right: 0,
            bottom: 10,
            color: "grey",
            cursor: "pointer",
          }}
          fontSize="small"
        />
      </div>
      <div
        style={{
          height: "1.6px",
          backgroundColor: "grey",
          marginTop: "10px",
        }}
      ></div>
    </div>
  );
}
