import React, { useState, useEffect } from "react";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import FilterListIcon from "@mui/icons-material/FilterList";
import { User } from "../interfaces";

export function Dropdown({
  idx,
  original,
  setResults,
}: {
  idx: number;
  original: User[];
  setResults: (value: User[]) => void;
}) {
  // dropdown 오픈 여부
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLDivElement>) => {
    // console.log(event.currentTarget);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  // dropdown default값
  const [state, setState] = useState<string | null>(
    idx === 0 ? "정보 조회 최신순" : "정보 요청 최신순"
  );
  // click
  const changeState = (id: number) => {
    console.log(id);
    // setState(id)
    if (idx === 0) {
      id === 0 ? setState("정보 조회 최신순") : setState("남은 기간 짧은순");
    } else {
      id === 0 ? setState("정보 요청 최신순") : setState("정보 거절 최신순");
    }
  };

  // 정렬
  const resetSort = () => {
    setResults(original);
  };
  const ddaySort = () => {
    let newList = [...original];
    newList.sort((a: User, b: User): number => a.leftDay! - b.leftDay!);
    setResults(newList);
  };
  const refuseSort = () => {
    let newList = [...original];
    newList.sort(
      (a: User, b: User) =>
        new Date(b.refuseTime!).getTime() - new Date(a.refuseTime!).getTime()
    );
    setResults(newList);
  };

  return (
    <>
      <div
        style={{
          position: "absolute",
          top: 0,
          right: "1%",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          fontSize: "12px",
          color: "grey",
          cursor: idx !== 1 ? "pointer" : "default",
        }}
        onClick={handleClick}
      >
        <FilterListIcon
          style={{
            width: "16px",
            height: "16px",
            marginBottom: "3px",
            marginRight: "3px",
          }}
        />
        {state}
      </div>
      {/* dropdown */}
      {idx !== 1 ? (
        <Menu
          id="basic-menu"
          anchorEl={anchorEl}
          open={open}
          onClose={handleClose}
          MenuListProps={{
            "aria-labelledby": "basic-button",
          }}
        >
          <MenuItem
            onClick={() => {
              changeState(0);
              handleClose();
              resetSort();
            }}
            style={{ fontSize: "12px" }}
          >
            {idx === 0 ? "정보 조회 최신순" : "정보 요청 최신순"}
          </MenuItem>
          <MenuItem
            onClick={() => {
              changeState(1);
              handleClose();
              if (idx === 0) {
                ddaySort();
              } else {
                refuseSort();
              }
            }}
            style={{ fontSize: "12px" }}
          >
            {idx === 0 ? "남은 기간 짧은순" : "요청 거절 최신순"}
          </MenuItem>
        </Menu>
      ) : (
        <></>
      )}
    </>
  );
}
