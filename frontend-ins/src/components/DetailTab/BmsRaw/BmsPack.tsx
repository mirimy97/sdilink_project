import TableBody from "@mui/material/TableBody";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TableCell, { tableCellClasses } from "@mui/material/TableCell";
import { StyledTable } from "../../Table/ResultTable";
import { styled } from "@mui/material/styles";
import DownloadIcon from "@mui/icons-material/Download";
import Button from "@mui/material/Button";
import { LightTextField } from "../../../pages/Login";
import "./BmsRaw.css";
import axiosApi from "../../../axiosApi";
import { useAppSelector } from "../../../redux/hooks";
import { PackInfo, Props, csvPack } from "../../../interfaces";
import { useEffect, useState } from "react";
import { CSVLink } from "react-csv";

interface Data {
  batteryNum: string;
  volt: number;
  flow: number;
  temperature: number;
  state: number;
  SOC: number;
  SOH: number;
  cycle: number;
  createdAt: string;
}

// 팩: 전압, 전류, 온도, 상태, 용량, SOC, SOH, 충전사이클, 생성시간

interface HeadCell {
  disablePadding: boolean;
  id: keyof Data;
  label: string;
}

const headCells: readonly HeadCell[] = [
  {
    id: "batteryNum",
    disablePadding: false,
    label: "배터리팩 일련번호",
  },
  {
    id: "volt",
    disablePadding: false,
    label: "전압 (V)",
  },
  {
    id: "flow",
    disablePadding: false,
    label: "전류 (A)",
  },
  {
    id: "temperature",
    disablePadding: false,
    label: "온도 (℃)",
  },
  {
    id: "state",
    disablePadding: false,
    label: "상태",
  },
  {
    id: "SOC",
    disablePadding: false,
    label: "SOC (%)",
  },
  {
    id: "SOH",
    disablePadding: false,
    label: "SOH (%)",
  },
  {
    id: "cycle",
    disablePadding: false,
    label: "충전사이클",
  },
  {
    id: "createdAt",
    disablePadding: false,
    label: "생성시간",
  },
];

function EnhancedTableHead() {
  return (
    <TableHead>
      <TableRow>
        {headCells.map((headCell) => (
          <StyledTableCell
            key={headCell.id}
            align={headCell.id === "batteryNum" ? "left" : "center"}
            padding="normal"
          >
            {headCell.label}
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

export function BmsPack({ props }: { props: Props }) {
  const [startDate, setStartDate] = useState(
    props.startDateString + "T" + props.startTimeString
  );
  const [endDate, setEndDate] = useState(props.nowTime);

  // 결과 리스트
  const [packList, setPackList] = useState<PackInfo[] | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    axiosApi
      .get(`/insurance/approvals/${props.approvalId}/bms/packs`, {
        headers: {
          Authorization: props.accessToken,
        },
        params: {
          startTime: props.startDateString + " " + props.startTimeString,
          endTime: props.nowTime,
          // endTime: props.EndDateString + " " + props.endTimeString,
        },
      })
      .then((res) => {
        // console.log(res.data.packList);
        setPackList(res.data.packList);
      })
      .then(() => setLoading(false))
      .catch((err) => console.log(err));
  }, []);

  const onClickHandler = () => {
    setLoading(true);
    axiosApi
      .get(`/insurance/approvals/${props.approvalId}/bms/packs`, {
        headers: {
          Authorization: props.accessToken,
        },
        params: {
          startTime: startDate.replace("T", " "),
          endTime: endDate!.replace("T", " "),
        },
      })
      .then((res) => {
        // console.log(res.data.packList);
        setPackList(res.data.packList);
      })
      .then(() => setLoading(false))
      .catch((err) => console.log(err));
  };

  // csv 다운로드
  const csvHeaders = [
    { label: "배터리팩 일련번호", key: "packNum" },
    { label: "전압 (V)", key: "voltageP" },
    { label: "전류 (A)", key: "current" },
    { label: "온도 (℃)", key: "tempP" },
    { label: "상태", key: "status" },
    { label: "SOC", key: "SOC" },
    { label: "SOH", key: "SOH" },
    { label: "충전 사이클", key: "cycle" },
    { label: "생성시간", key: "createdAt" },
  ];
  const [csvData, setCsvData] = useState<csvPack[] | null>(null);
  const userInfo = useAppSelector((store) => store.detail);

  useEffect(() => {
    if (packList) {
      const newList = packList.map((pack, index) => {
        return {
          packNum: index === 0 ? userInfo.packCode : "",
          voltageP: pack.voltageP,
          current: pack.current,
          tempP: pack.tempP,
          status: pack.status,
          SOC: pack.soc,
          SOH: pack.soh,
          cycle: pack.cycle,
          createdAt: pack.createdAt,
        };
      });
      setCsvData(newList);
    }
  }, [packList]);

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
            defaultValue={props.nowTime}
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
      </div>
      {loading ? (
        <div
          style={{
            color: "#bbbbbb",
            fontWeight: "bold",
          }}
        >
          결과 조회 중입니다.
        </div>
      ) : (
        <TableContainer sx={{ maxHeight: 400 }}>
          <StyledTable sx={{ minWidth: 750 }} aria-labelledby="tableTitle">
            <EnhancedTableHead />
            <TableBody>
              {packList &&
                packList.map((pack, index) => {
                  return (
                    <StyledTableRow key={pack.id} sx={{ cursor: "pointer" }}>
                      <StyledTableCell align="left">
                        {index === 0 ? pack.packCode : ""}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.voltageP}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.current}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.tempP.toFixed(0)}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.status}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.soc}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.soh * 100}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.cycle}
                      </StyledTableCell>
                      <StyledTableCell align="center">
                        {pack.createdAt}
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
