import { useNavigate } from "react-router-dom";
import { RecentUser } from "../interfaces";

export function RecentListItem({ item }: { item: RecentUser }) {
  const imgSrc = `/assets/basicImg/${item.carInfoId}.png`;
  const navigate = useNavigate();
  return item.isExpired ? (
    <></>
  ) : (
    <div
      style={{
        width: "28vw",
        height: "15vh",
        backgroundColor: "#303030",
        marginRight: "30px",
        padding: "10px",
        borderRadius: "10px",
        display: "flex",
        alignItems: "center",
        marginBottom: "15px",
        cursor: "pointer",
      }}
      onClick={() => {
        navigate(`/detail/${item.carId}`, {
          state: {
            userName: item.name,
            approvalId: item.approvalId,
          },
        });
      }}
    >
      <img src={imgSrc} alt="차종" width="150px" />
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          lineHeight: "27px",
          color: "#7F7F7F",
          fontSize: "14px",
          marginLeft: "20px",
          marginRight: "25px",
        }}
      >
        <span>차량 소유주명</span>
        <span>차종</span>
        <span>배터리팩 일련번호</span>
        <span>정보 조회 일시</span>
      </div>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          lineHeight: "27px",
          color: "#bbbbbb",
          fontSize: "14px",
          fontWeight: "bold",
        }}
      >
        <span>{item.name}</span>
        <span>{item.modelName}</span>
        <span>{item.packCode}</span>
        <span>{item.createdAt}</span>
      </div>
    </div>
  );
}
