import { User } from "../../interfaces";
import TableCell from "@mui/material/TableCell";
import TableRow from "@mui/material/TableRow";
import { useNavigate } from "react-router-dom";
import { useAppDispatch } from "../../redux/hooks";
import { goToDetail } from "../../redux/detail";
import "./Table.css";

export function TableListItem({
  props,
  id,
  idx,
  onClickHandler,
}: {
  props: User;
  id: number;
  idx: number;
  onClickHandler: (i: number) => void;
}) {
  // 상세 페이지 이동 -> redux 상태관리 필요
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const goDetail = (props: User) => {
    dispatch(goToDetail(props));
    navigate(`/detail/${props.carId}`, {
      state: {
        userName: props.userName,
        approvalId: props.id,
      },
    });
  };

  const className = `MuiTableRow-${id % 2 ? "odd" : "even"}`;

  return idx === 0 ? (
    <TableRow className={className}>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {id}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.userName}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.carNumber}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.authTime}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.endTime}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        D-{props.leftDay === 0 ? "Day" : props.leftDay}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        <span
          style={{ cursor: "pointer", wordBreak: "keep-all" }}
          onClick={() => goDetail(props)}
          className="goToDetail"
        >
          자세히보기
        </span>
      </TableCell>
    </TableRow>
  ) : idx === 1 ? (
    <TableRow className={className}>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {id}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.userName}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.carNumber}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.createdAt}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        <span
          style={{ cursor: "pointer", wordBreak: "keep-all" }}
          onClick={() => onClickHandler(props.carId!)}
          className="goToDetail"
        >
          앱 푸쉬 알림 보내기
        </span>
      </TableCell>
    </TableRow>
  ) : (
    <TableRow className={className}>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {id}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.userName}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.carNumber}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.createdAt}
      </TableCell>
      <TableCell align="center" sx={{ padding: "12px" }}>
        {props.refuseTime}
      </TableCell>
      <TableCell sx={{ padding: "12px" }}>
        <span
          style={{ cursor: "pointer", wordBreak: "keep-all" }}
          onClick={() => onClickHandler(props.carId!)}
          className="goToDetail"
        >
          정보 조회 재요청
        </span>
      </TableCell>
    </TableRow>
  );
}
