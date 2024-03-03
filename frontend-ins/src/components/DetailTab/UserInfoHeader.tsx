import { useAppSelector } from "../../redux/hooks";

export function UserInfoHeader() {
  const userInfo = useAppSelector((store) => store.detail);
  const imgSrc = `/assets/basicImg/${userInfo.carInfoId}.png`;
  const year =
    userInfo.birth[0] === "0"
      ? "20" + userInfo.birth.substr(0, 2)
      : "19" + userInfo.birth.substr(0, 2); // 앞에 '19'를 추가하여 연도 생성
  const month = userInfo.birth.substr(2, 2);
  const day = userInfo.birth.substr(4, 2);
  return (
    <div
      style={{
        height: "20%",
        backgroundColor: "#282828",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-evenly",
      }}
    >
      <img src={imgSrc} alt={userInfo.modelName} height="70%" />
      <div
        style={{
          width: "90%",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div className="lineOdd">
          <span>생년월일</span>
          <span>{year + "-" + month + "-" + day}</span>
        </div>
        <div className="lineEven">
          <span>차종</span>
          <span>{userInfo.modelName}</span>
        </div>
        <div className="lineOdd">
          <span>차량번호</span>
          <span>{userInfo.carNum}</span>
        </div>
        <div className="lineEven">
          <span>배터리팩 일련번호</span>
          <span>{userInfo.packCode}</span>
        </div>
      </div>
    </div>
  );
}
