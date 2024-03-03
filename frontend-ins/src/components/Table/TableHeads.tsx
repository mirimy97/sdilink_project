import TableCell from "@mui/material/TableCell";
import TableRow from "@mui/material/TableRow";
import TableHead from "@mui/material/TableHead";
import "./Table.css";

export function TableHeads({ idx }: { idx: number }) {
  return (
    <TableHead>
      {idx === 0 ? (
        <TableRow>
          <TableCell align="center" sx={{ padding: "12px", width: "6%" }}>
            #
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "14%", wordBreak: "keep-all" }}
          >
            차량 소유주명
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "14%", wordBreak: "keep-all" }}
          >
            차량 번호
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            정보 조회 시작 일시
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            정보 조회 종료 일시
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "10%", wordBreak: "keep-all" }}
          >
            남은 기간
          </TableCell>
          <TableCell align="center"> &nbsp; &nbsp; &nbsp; &nbsp;</TableCell>
        </TableRow>
      ) : idx === 1 ? (
        <TableRow>
          <TableCell align="center" sx={{ padding: "12px", width: "6%" }}>
            #
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            차량 소유주명
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            차량 번호
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            정보 요청 일시
          </TableCell>
          <TableCell align="center">
            {" "}
            &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;
          </TableCell>
        </TableRow>
      ) : (
        <TableRow>
          <TableCell align="center" sx={{ padding: "12px", width: "6%" }}>
            #
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            차량 소유주명
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            차량 번호
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            정보 요청 일시
          </TableCell>
          <TableCell
            align="center"
            sx={{ padding: "12px", width: "20%", wordBreak: "keep-all" }}
          >
            요청 거절 일시
          </TableCell>
          <TableCell align="center">
            {" "}
            &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;
          </TableCell>
        </TableRow>
      )}
    </TableHead>
  );
}
