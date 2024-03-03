import { ResultTable } from "./Table/ResultTable";
import "./UserList.css";
import { User } from "../interfaces";
import React, { useState } from "react";

export function UserList({
  props,
  idx,
  onClickHandler,
}: {
  props: User[];
  idx: number;
  onClickHandler: (i: number) => void;
}) {
  // 필터링이나 검색 기능 필요 -> results 유동적으로 변경됨
  const [results, setResults] = useState<User[]>(props);
  // 검색 기능
  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // console.log(e.target.value);
    const searchRes = props.filter(
      (item) =>
        item.userName.includes(e.target.value) ||
        item.carNumber.includes(e.target.value)
    );
    setResults(searchRes);
  };

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
  };

  return (
    <div
      style={{
        position: "relative",
        padding: "10px",
      }}
    >
      <form
        style={{
          position: "absolute",
          right: "1%",
          top: "-36px",
          width: "25%",
        }}
        onSubmit={onSubmit}
      >
        <input
          type="search"
          placeholder="  차량 소유주명이나 차량 번호를 입력하세요"
          onChange={onChange}
          className="input"
          style={{ backgroundColor: "inherit", borderRadius: "5px" }}
        />
      </form>
      {/* <Dropdown idx={idx} original={props} setResults={setResults} /> */}
      <ResultTable
        results={results}
        idx={idx}
        onClickHandler={onClickHandler}
      />
    </div>
  );
}
