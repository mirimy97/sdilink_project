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
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import FormControl from "@mui/material/FormControl";
import Select, { SelectChangeEvent } from "@mui/material/Select";
import {
  Props,
  ModuleCellsMapping,
  ModuleInfo,
  csvModule,
} from "../../../interfaces";
import { useState } from "react";
import axiosApi from "../../../axiosApi";
import { useAppSelector } from "../../../redux/hooks";
import { CSVLink } from "react-csv";

interface Data {
  packNum: string;
  moduleNum: string;
  volt: number;
  temperature: number;
  outlier: number;
  createdAt: string;
}

export const CustomSelect = styled(Select)(({ theme }) => ({
  height: theme.spacing(3.5), // 박스의 높이를 설정합니다.
  color: "#bbbbbb", // 글자 색상을 설정합니다.
  "& .MuiSelect-icon": {
    color: "#bbbbbb", // 드롭다운 아이콘의 색상을 설정합니다.
  },
  "& .MuiSelect-selectMenu": {
    paddingTop: theme.spacing(0.5), // 글자와 상단 간격을 조정합니다.
    paddingBottom: theme.spacing(0.5), // 글자와 하단 간격을 조정합니다.
    fontSize: "12px", // 글꼴 크기를 설정합니다.
  },
  "& .MuiSelect-select": {
    borderColor: "#bbbbbb", // border 색상을 설정합니다.
  },
  "& .MuiOutlinedInput-notchedOutline": {
    borderColor: "#bbbbbb", // outlined 모드에서의 border 색상을 설정합니다.
  },
  "&:hover .MuiOutlinedInput-notchedOutline": {
    borderColor: "#bbbbbb", // 호버 상태일 때 outlined 모드에서의 border 색상을 설정합니다.
  },
  "& .MuiInputLabel-root": {
    fontSize: "12px", // 원하는 레이블 글자 크기를 설정합니다.
    color: "#bbbbbb", // 원하는 레이블 글자 색상을 설정합니다.
  },
}));

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
    id: "volt",
    disablePadding: false,
    label: "전압 (V)",
  },
  {
    id: "temperature",
    disablePadding: false,
    label: "온도 (℃)",
  },
  {
    id: "outlier",
    disablePadding: false,
    label: "이상치 통계",
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
    <TableHead sx={{ height: "40px" }}>
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

export function BmsModule({
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

  const [selectedModule, setSelectedModule] = React.useState("");
  const handleChange = (event: SelectChangeEvent<unknown>) => {
    const selectedValue = event.target.value as string;
    setSelectedModule(selectedValue);
  };
  // 모듈 들어있는 배열 (Object.keys가 순서 보장 안되기 때문에, sort함)
  const moduleArr = Object.keys(moduleCellMapping!).sort();
  // 조회 일시 데이터
  const [startDate, setStartDate] = useState(
    props.startDateString + "T" + props.startTimeString
  );
  const [endDate, setEndDate] = useState(props.nowTime);

  const [notSearch, setNotSearch] = useState(true);
  const [moduleList, setModuleList] = useState<ModuleInfo[] | null>(null);

  // 조회
  const packNum = useAppSelector((store) => store.detail.packCode);
  const onClickHandler = () => {
    if (notSearch) {
      setNotSearch(false);
    }
    axiosApi(`/insurance/approvals/${props.approvalId}/bms/modules`, {
      headers: {
        Authorization: props.accessToken,
      },
      params: {
        moduleCode: selectedModule,
        startTime: startDate.replace("T", " "),
        endTime: endDate,
      },
    })
      .then((res) => {
        // console.log(res.data);
        setModuleList(res.data.moduleList);
      })
      .catch((err) => console.log(err));
  };

  // csv 다운로드
  const csvHeaders = [
    { label: "배터리팩 일련번호", key: "packNum" },
    { label: "배터리모듈 일련번호", key: "moduleNum" },
    { label: "전압 (V)", key: "voltageM" },
    { label: "온도 (℃)", key: "tempM" },
    { label: "이상치 통계", key: "outlier" },
    { label: "생성시간", key: "createdAt" },
  ];
  const [csvData, setCsvData] = useState<csvModule[] | null>(null);
  const userInfo = useAppSelector((store) => store.detail);

  React.useEffect(() => {
    if (moduleList) {
      const newList = moduleList.map((module, index) => {
        return {
          packNum: index === 0 ? userInfo.packCode : "",
          moduleNum: index === 0 ? module.moduleCode : "",
          voltageM: module.voltage,
          tempM: module.temp,
          outlier: module.outlier,
          createdAt: module.createdAt,
        };
      });
      setCsvData(newList);
    }
  }, [moduleList]);

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
              onChange={(event) => handleChange(event)}
            >
              {moduleArr.map((module) => (
                <MenuItem key={module} value={module}>
                  {module}
                </MenuItem>
              ))}
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
            defaultValue={props.startDateString + "T" + props.startTimeString}
            InputLabelProps={{
              shrink: true,
              style: { fontSize: "12px" },
            }}
            required
            onChange={(e) => {
              const value = e.target.value;
              setStartDate((prevStartDate) => {
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
            defaultValue={props.nowTime}
            InputLabelProps={{
              shrink: true,
              style: { fontSize: "12px" },
            }}
            onChange={(e) => {
              const value = e.target.value;
              setEndDate((prevEndDate) => {
                return value;
              });
            }}
            required
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
          모듈과 기간 선택 후 결과 조회가 가능합니다.
        </div>
      ) : moduleList === null ? (
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
              {moduleList &&
                moduleList.map((module, index) => {
                  return (
                    <StyledTableRow key={module.id} sx={{ cursor: "pointer" }}>
                      <StyledTableCell align="left">
                        {index === 0 ? packNum : ""}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "32px" }}
                      >
                        {index === 0 ? module.moduleCode : ""}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "38px" }}
                      >
                        {module.voltage}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "38px" }}
                      >
                        {module.temp}
                      </StyledTableCell>
                      <StyledTableCell
                        align="center"
                        style={{ paddingRight: "38px" }}
                      >
                        {module.outlier}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {module.createdAt}
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
