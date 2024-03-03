import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Typography from "@mui/material/Typography";
import Box from "@mui/material/Box";
import { styled } from "@mui/material/styles";
import React, { useState } from "react";
import { BmsPack } from "./BmsPack";
import { BmsModule } from "./BmsModule";
import { BmsCell } from "./BmsCell";
import { useLocation } from "react-router-dom";
import { useAppSelector } from "../../../redux/hooks";
import { ModuleCellsMapping } from "../../../interfaces";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box>
          <Typography>{children}</Typography>
        </Box>
      )}
    </div>
  );
}

function a11yProps(index: number) {
  return {
    id: `simple-tab-${index}`,
    "aria-controls": `simple-tabpanel-${index}`,
  };
}

export function BmsTab({
  moduleCellMapping,
  nowTime,
}: {
  moduleCellMapping: ModuleCellsMapping | null;
  nowTime: string | null;
}) {
  // 탭 선택
  const [value, setValue] = useState<number>(0);
  const handleChange = (event: React.SyntheticEvent, newValue: number) => {
    setValue(newValue);
  };

  const StyledTab = styled(Tab)({
    "&.MuiTab-root": {
      color: "#7F7F7F",
      fontWeight: "bold",
    },
    "&.Mui-selected": {
      color: "#167BFF",
      fontWeight: "bold",
    },
  });
  const CustomTabs = styled(Tabs)(({ theme }) => ({
    "& .MuiTab-root": {
      height: "10px",
    },
  }));

  const location = useLocation();
  const approvalId = location.state.approvalId;
  const accessToken = useAppSelector((store) => store.insurance.token);

  // default 날짜 계산 -> Now Time
  // const today = new Date();
  // const endYear = today.getFullYear();
  // const endMonth = ("0" + (today.getMonth() + 1)).slice(-2);
  // const endDay = ("0" + today.getDate()).slice(-2);
  // const endHours = ("0" + today.getHours()).slice(-2);
  // const endMinutes = ("0" + today.getMinutes()).slice(-2);
  // const endTimeString = endHours + ":" + endMinutes;
  // const EndDateString = endYear + "-" + endMonth + "-" + endDay;

  // 하루 전부터 조회 시작해도 될 듯 (주행거리 기준 3시간)
  const oneDayAgo = new Date(new Date(nowTime!).getTime() - 3 * 60 * 60 * 1000); // 1일 전의 날짜를 계산합니다.
  // 년, 월, 일을 가져옵니다.
  const startYear = oneDayAgo.getFullYear();
  const startMonth = ("0" + (oneDayAgo.getMonth() + 1)).slice(-2); // 월은 0부터 시작하므로 1을 더해줍니다.
  const startDay = ("0" + oneDayAgo.getDate()).slice(-2);
  const startHours = ("0" + oneDayAgo.getHours()).slice(-2);
  const startMinutes = ("0" + oneDayAgo.getMinutes()).slice(-2);
  const startTimeString = startHours + ":" + startMinutes;
  const startDateString = startYear + "-" + startMonth + "-" + startDay;

  const props = {
    startDateString,
    // EndDateString,
    // endTimeString,
    startTimeString,
    approvalId,
    accessToken,
    nowTime,
  };

  return (
    <div
      style={{
        height: "100%",
        backgroundColor: "#303030",
        position: "relative",
      }}
    >
      <Box>
        <CustomTabs
          value={value}
          onChange={handleChange}
          aria-label="basic tabs example"
          TabIndicatorProps={{ style: { display: "none" } }}
        >
          <StyledTab label="배터리 팩" {...a11yProps(0)} />
          <StyledTab label="배터리 모듈" {...a11yProps(1)} />
          <StyledTab label="배터리 셀" {...a11yProps(2)} />
        </CustomTabs>
      </Box>
      <div
        style={{
          height: "90%",
          backgroundColor: "#303030",
        }}
      >
        <TabPanel value={value} index={0}>
          <BmsPack props={props} />
        </TabPanel>
        <TabPanel value={value} index={1}>
          <BmsModule moduleCellMapping={moduleCellMapping} props={props} />
        </TabPanel>
        <TabPanel value={value} index={2}>
          <BmsCell moduleCellMapping={moduleCellMapping} props={props} />
        </TabPanel>
      </div>
    </div>
  );
}
