import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Typography from "@mui/material/Typography";
import Box from "@mui/material/Box";
import { styled } from "@mui/material/styles";
import React, { useState } from "react";
import { UserList } from "../components/UserList";
import { User } from "../interfaces";

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

interface Ilist {
  acceptList: User[] | never;
  waitList: User[] | never;
  refuseList: User[] | never;
  onClickHandler: (i: number) => void;
}

export function CustomList({
  acceptList,
  waitList,
  refuseList,
  onClickHandler,
}: Ilist) {
  // const [acceptList, setAcceptList] = useState<User[] | null>(results.accept);
  // const [waitList, setWaitList] = useState<User[] | null>(results.waiting);
  // const [refuseList, setRefuseList] = useState<User[] | null>(results.refuse);
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
      color: "white",
      fontWeight: "bold",
    },
  });
  return (
    <div style={{ height: "53vh", backgroundColor: "#303030" }}>
      <Box>
        <Tabs
          value={value}
          onChange={handleChange}
          aria-label="basic tabs example"
          TabIndicatorProps={{ style: { display: "none" } }}
          // sx={{ ".Mui-selected": { color: "black", fontWeight: "bold" } }}
        >
          <StyledTab label="승인 완료" {...a11yProps(0)} />
          <StyledTab label="승인 대기" {...a11yProps(1)} />
          <StyledTab label="승인 거절" {...a11yProps(2)} />
        </Tabs>
      </Box>
      <TabPanel value={value} index={0}>
        {acceptList && (
          <UserList
            props={acceptList}
            idx={0}
            onClickHandler={onClickHandler}
          />
        )}
      </TabPanel>
      <TabPanel value={value} index={1}>
        {waitList && (
          <UserList props={waitList} idx={1} onClickHandler={onClickHandler} />
        )}
      </TabPanel>
      <TabPanel value={value} index={2}>
        {refuseList && (
          <UserList
            props={refuseList}
            idx={2}
            onClickHandler={onClickHandler}
          />
        )}
      </TabPanel>
    </div>
  );
}
