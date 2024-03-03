import * as React from "react";
import Box from "@mui/material/Box";
import TableBody from "@mui/material/TableBody";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TableSortLabel from "@mui/material/TableSortLabel";
import TableCell, { tableCellClasses } from "@mui/material/TableCell";
import { visuallyHidden } from "@mui/utils";
import { StyledTable } from "../../Table/ResultTable";
import { styled } from "@mui/material/styles";
import Button from "@mui/material/Button";
import { LightTextField } from "../../../pages/Login";
import DownloadIcon from "@mui/icons-material/Download";
import { CustomSelect } from "./BmsModule";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import FormControl from "@mui/material/FormControl";
import { SelectChangeEvent } from "@mui/material/Select";
import {
  CellInfo,
  ModuleCellsMapping,
  Props,
  csvCell,
} from "../../../interfaces";
import axiosApi from "../../../axiosApi";
import { useAppSelector } from "../../../redux/hooks";
import { CSVLink } from "react-csv";

interface Data {
  packNum: string;
  moduleNum: string;
  cellNum: string;
  volt: number;
  outlier: number;
  createdAt: string;
}

type Order = "asc" | "desc";

interface HeadCell {
  disablePadding: boolean;
  id: keyof Data;
  label: string;
}

const headCells: readonly HeadCell[] = [
  {
    id: "packNum",
    disablePadding: false,
    label: "배터리팩 일련번호",
  },
  {
    id: "moduleNum",
    disablePadding: false,
    label: "배터리모듈 일련번호",
  },
  {
    id: "cellNum",
    disablePadding: false,
    label: "배터리셀 일련번호",
  },
  {
    id: "volt",
    disablePadding: false,
    label: "전압 (V)",
  },
  {
    id: "outlier",
    disablePadding: false,
    label: "이상치",
  },
  {
    id: "createdAt",
    disablePadding: false,
    label: "생성시간",
  },
];

interface EnhancedTableProps {
  onRequestSort: (
    event: React.MouseEvent<unknown>,
    property: keyof Data
  ) => void;
  order: Order;
  orderBy: string;
}

function EnhancedTableHead(props: EnhancedTableProps) {
  const { order, orderBy, onRequestSort } = props;
  const createSortHandler =
    (property: keyof Data) => (event: React.MouseEvent<unknown>) => {
      onRequestSort(event, property);
    };

  return (
    <TableHead>
      <TableRow>
        {headCells.map((headCell) => (
          <StyledTableCell
            key={headCell.id}
            align={headCell.id === "packNum" ? "left" : "center"}
            padding="normal"
            sortDirection={orderBy === headCell.id ? order : false}
            width="3%"
          >
            <TableSortLabel
              active={orderBy === headCell.id}
              direction={orderBy === headCell.id ? order : "asc"}
              onClick={createSortHandler(headCell.id)}
            >
              {headCell.label}
              {orderBy === headCell.id ? (
                <Box component="span" sx={visuallyHidden}>
                  {order === "desc" ? "sorted descending" : "sorted ascending"}
                </Box>
              ) : null}
            </TableSortLabel>
          </StyledTableCell>
        ))}
      </TableRow>
    </TableHead>
  );
}

// 색상 커스텀
const StyledTableCell = styled(TableCell)(() => ({
  [`&.${tableCellClasses.head}`]: {
    backgroundColor: "#bbbbbb",
    padding: "14px",
    color: "black",
  },
  [`&.${tableCellClasses.body}`]: {
    fontSize: 14,
    padding: "14px",
  },
}));

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  "&:nth-of-type(even)": {
    backgroundColor: "#404040",
  },
  "&:nth-of-type(odd)": {
    backgroundColor: "#303030",
  },
}));

export function BmsCell({
  moduleCellMapping,
  props,
}: {
  moduleCellMapping: ModuleCellsMapping | null;
  props: Props;
}) {
  const [order, setOrder] = React.useState<Order>("asc");
  const [orderBy, setOrderBy] = React.useState<keyof Data>("createdAt");

  const handleRequestSort = (
    event: React.MouseEvent<unknown>,
    property: keyof Data
  ) => {
    const isAsc = orderBy === property && order === "asc";
    setOrder(isAsc ? "desc" : "asc");
    setOrderBy(property);
  };

  // 모듈 들어있는 배열 (Object.keys가 순서 보장 안되기 때문에, sort함)
  const moduleArr = Object.keys(moduleCellMapping!).sort();
  const [cells, setCells] = React.useState<string[]>([]);
  // 모듈 선택
  const [selectedModule, setSelectedModule] = React.useState("");
  const handleChangeModule = (event: SelectChangeEvent<unknown>) => {
    const module = event.target.value as string;
    setSelectedModule(module);
    setSelectedCell("");
    setCells(moduleCellMapping![module]);
  };
  const [selectedCell, setSelectedCell] = React.useState("");
  const handleChangeCell = (event: SelectChangeEvent<unknown>) => {
    const cell = event.target.value as string;
    setSelectedCell(cell);
  };
  // 조회 일시
  const [startDate, setStartDate] = React.useState(
    props.startDateString + "T" + props.startTimeString
  );
  const [endDate, setEndDate] = React.useState(props.nowTime);
  const [cellList, setCellList] = React.useState<CellInfo[] | null>(null);
  // 분기
  const [notSearch, setNotSearch] = React.useState(true);
  // pack
  const packNum = useAppSelector((store) => store.detail.packCode);

  const onClickHandler = () => {
    if (notSearch) {
      setNotSearch(false);
    }
    if (cellList) {
      setCellList(null);
    }
    axiosApi
      .get(`/insurance/approvals/${props.approvalId}/bms/cells`, {
        headers: {
          Authorization: props.accessToken,
        },
        params: {
          moduleCode: selectedModule,
          cellCode: selectedCell,
          startTime: startDate.replace("T", " "),
          endTime: endDate,
        },
      })
      .then((res) => {
        // console.log(res.data.cellList);
        setCellList(res.data.cellList);
      })
      .catch((err) => console.log(err));
  };

  // csv 다운로드
  const csvHeaders = [
    { label: "배터리팩 일련번호", key: "packNum" },
    { label: "배터리모듈 일련번호", key: "moduleNum" },
    { label: "배터리셀 일련번호", key: "cellNum" },
    { label: "전압 (V)", key: "voltageC" },
    { label: "이상치", key: "outlier" },
    { label: "생성시간", key: "createdAt" },
  ];
  const [csvData, setCsvData] = React.useState<csvCell[] | null>(null);
  const userInfo = useAppSelector((store) => store.detail);

  React.useEffect(() => {
    if (cellList) {
      const newList = cellList.map((cell, index) => {
        return {
          packNum: index === 0 ? userInfo.packCode : "",
          moduleNum: index === 0 ? selectedModule : "",
          cellNum: index === 0 ? cell.cellCode : "",
          voltageC: cell.voltageC,
          outlier: cell.outlier,
          createdAt: cell.createdAt,
        };
      });
      setCsvData(newList);
    }
  }, [cellList]);

  return (
    <div
      style={{
        paddingLeft: "16px",
        paddingRight: "16px",
        height: "100%",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          height: "35px",
          marginBottom: "7px",
          position: "relative",
        }}
      >
        <div style={{ position: "absolute", top: 9, left: 0 }}>
          <FormControl sx={{ width: "180px" }} size="small">
            <InputLabel
              id="module-select-label"
              sx={{ fontSize: "12px", color: "#bbbbbb", marginTop: "-2px" }}
            >
              모듈 선택
            </InputLabel>
            <CustomSelect
              labelId="module-select-label"
              id="module-select"
              value={selectedModule}
              label="모듈 선택"
              onChange={(event) => handleChangeModule(event)}
            >
              {moduleArr.map((module) => (
                <MenuItem key={module} value={module}>
                  {module}
                </MenuItem>
              ))}
            </CustomSelect>
          </FormControl>
        </div>
        <div style={{ position: "absolute", top: 9, left: 200 }}>
          <FormControl sx={{ width: "180px" }} size="small">
            <InputLabel
              id="cell-select-label"
              sx={{ fontSize: "12px", color: "#bbbbbb", marginTop: "-2px" }}
            >
              셀 선택
            </InputLabel>
            <CustomSelect
              labelId="cell-select-label"
              id="cell-select"
              value={selectedCell}
              label="셀 선택"
              onChange={(event) => handleChangeCell(event)}
            >
              {selectedModule !== "" ? (
                cells.map((cell) => (
                  <MenuItem key={cell} value={cell}>
                    {cell}
                  </MenuItem>
                ))
              ) : (
                <MenuItem
                  sx={{
                    fontSize: "14px",
                    paddingTop: "2px",
                    paddingBottom: "2px",
                  }}
                >
                  모듈을 선택해주세요
                </MenuItem>
              )}
            </CustomSelect>
          </FormControl>
        </div>
        <div style={{ position: "absolute", top: 9, right: 400 }}>
          <LightTextField
            inputProps={{
              step: 60,
              style: {
                fontSize: "12px",
                padding: 5,
              },
            }}
            type="datetime-local"
            size="small"
            label="조회시작일시"
            defaultValue={startDate}
            InputLabelProps={{
              shrink: true,
              style: { fontSize: "12px" },
            }}
            required
            onChange={(e) => {
              const value = e.target.value;
              setStartDate((prevStartDate) => {
                // 상태 업데이트 로직
                return value;
              });
            }}
          />
        </div>
        <div style={{ position: "absolute", top: 9, right: 200 }}>
          <LightTextField
            inputProps={{
              step: 60,
              style: { fontSize: "12px", padding: 5 },
            }}
            type="datetime-local"
            size="small"
            label="조회종료일시"
            defaultValue={endDate}
            InputLabelProps={{
              shrink: true,
              style: { fontSize: "12px" },
            }}
            required
            onChange={(e) => {
              const value = e.target.value;
              setEndDate((prevEndDate) => {
                // 상태 업데이트 로직
                return value;
              });
            }}
          />
        </div>
        <div
          style={{
            position: "absolute",
            top: 9,
            right: 100,
            display: "flex",
            alignItems: "center",
          }}
        >
          <Button
            variant="contained"
            size="small"
            style={{
              backgroundColor: "#7F7F7F",
              height: "26px",
            }}
            onClick={onClickHandler}
          >
            조회
          </Button>
        </div>
        {csvData && (
          <CSVLink
            data={csvData!}
            headers={csvHeaders}
            filename={`${userInfo.userName}(${userInfo.carNum})-${startDate}-${endDate}`}
          >
            <div
              style={{
                position: "absolute",
                top: 5,
                right: 0,
                display: "flex",
                flexDirection: "column",
                fontSize: "10px",
                justifyContent: "center",
                alignItems: "center",
                color: "#7f7f7f",
              }}
            >
              <span>
                <DownloadIcon />
              </span>
              <span style={{ marginTop: "-11px" }}>csv</span>
            </div>
          </CSVLink>
        )}
        {/* <div
          style={{
            position: "absolute",
            top: 5,
            right: 0,
            display: "flex",
            flexDirection: "column",
            fontSize: "10px",
            justifyContent: "center",
            alignItems: "center",
            color: "#7f7f7f",
          }}
        >
          <span>
            <DownloadIcon />
          </span>
          <span style={{ marginTop: "-11px" }}>csv</span>
        </div> */}
      </div>
      {notSearch ? (
        <div
          style={{ color: "#bbbbbb", fontWeight: "bold", paddingTop: "10px" }}
        >
          모듈, 셀, 기간 선택 후 결과 조회가 가능합니다.
        </div>
      ) : cellList === null ? (
        <div
          style={{ color: "#bbbbbb", fontWeight: "bold", paddingTop: "10px" }}
        >
          결과 조회 중입니다.
        </div>
      ) : (
        <TableContainer sx={{ maxHeight: 400 }}>
          <StyledTable
            stickyHeader
            sx={{ minWidth: 750 }}
            aria-labelledby="tableTitle"
          >
            <EnhancedTableHead
              order={order}
              orderBy={orderBy}
              onRequestSort={handleRequestSort}
            />
            <TableBody>
              {cellList &&
                cellList.map((cell, index) => {
                  return (
                    <StyledTableRow key={cell.id} sx={{ cursor: "pointer" }}>
                      <StyledTableCell align="left">
                        {index === 0 ? packNum : ""}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "38px" }}
                      >
                        {index === 0 ? selectedModule : ""}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "36px" }}
                      >
                        {index === 0 ? cell.cellCode : ""}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "38px" }}
                      >
                        {cell.voltageC}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "38px" }}
                      >
                        {cell.outlier}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {cell.createdAt}
                      </StyledTableCell>
                    </StyledTableRow>
                  );
                })}
            </TableBody>
          </StyledTable>
        </TableContainer>
      )}
    </div>
  );
}
