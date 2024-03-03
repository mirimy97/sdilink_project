import { useState } from "react";
import TextField from "@mui/material/TextField";
import InputAdornment from "@mui/material/InputAdornment";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import styled from "styled-components";
import Button from "@mui/material/Button";
import { Toast } from "./Toast";
import axiosApi from "../axiosApi";
import { useAppSelector } from "../redux/hooks";

const WhiteBorderTextField = styled(TextField)`
  & label.Mui-focused {
    color: white;
  }
  & .MuiOutlinedInput-root {
    & fieldset {
      border-color: white;
    }
    &:hover fieldset {
      border-color: white;
    }
    &.Mui-focused fieldset {
      border-color: white;
    }
  }
`;

interface IToken {
  isToken: boolean;
  setIsToken: (a: boolean) => void;
  apiTokenInfo: {
    apiToken: string;
    createdAt: string;
    expiredAt: string;
    leftDate: number;
  };
  checkToken: () => void;
}

export function TokenManage({
  isToken,
  setIsToken,
  apiTokenInfo,
  checkToken,
}: IToken) {
  // token
  // const accessToken = localStorage.getItem("token");
  const accessToken = useAppSelector((store) => store.insurance.token);
  // 보험사 토큰 (api 요청)

  const [message, setMessage] = useState<string>("");
  const [toastState, setToastState] = useState<boolean>(false);
  const handleCopyClipBoard = (text: string) => {
    try {
      navigator.clipboard.writeText(text);
      setMessage("클립보드에 복사되었습니다.");
      setToastState(true);
    } catch (error) {
      setMessage("클립보드 복사에 실패하였습니다.");
      setToastState(true);
    }
  };

  // 토큰 발급
  const makeToken = () => {
    // console.log(accessToken);
    axiosApi
      .post(
        "/insurance/api/token",
        {},
        {
          headers: {
            Authorization: accessToken,
          },
        }
      )
      .then((res) => {
        // console.log(res.data);
        checkToken();
      })
      .then(() => setIsToken(true))
      .catch((err) => console.log(err));
  };

  // 토큰 삭제
  const deleteToken = () => {
    axiosApi
      .delete("/insurance/api/token", {
        headers: {
          Authorization: accessToken,
        },
      })
      .then(() => setIsToken(false))
      .catch((err) => console.log(err));
  };

  return isToken ? (
    <div
      style={{
        height: "26vh",
        backgroundColor: "#303030",
        padding: "10px 20px",
      }}
    >
      <div
        style={{
          margin: "10px 20px 10px 20px",
          display: "flex",
          justifyContent: "space-between",
          // paddingRight: "20px",
        }}
      >
        <div style={{ position: "relative" }}>
          <WhiteBorderTextField
            id="outlined-uncontrolled"
            label="토큰"
            value={apiTokenInfo.apiToken}
            // disabled
            size="small"
            sx={{ width: "600px", fontSize: "12px" }}
            color="primary"
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "center",
                      cursor: "pointer",
                    }}
                    onClick={() => handleCopyClipBoard(apiTokenInfo.apiToken)}
                  >
                    <ContentCopyIcon
                      fontSize="small"
                      sx={{ color: "#bbbbbb" }}
                    />
                  </div>
                </InputAdornment>
              ),
              style: { color: "white" },
              readOnly: true,
            }}
            InputLabelProps={{
              style: { color: "white" },
            }}
          />
          {toastState ? (
            <Toast
              message={message}
              toastState={toastState}
              setToastState={setToastState}
            />
          ) : null}
        </div>
        <div>
          <Button
            variant="contained"
            style={{ backgroundColor: "#1428A0", marginRight: "20px" }}
            onClick={makeToken}
          >
            토큰 재발급
          </Button>
          <Button
            variant="contained"
            style={{ backgroundColor: "#7F7F7F" }}
            onClick={deleteToken}
          >
            삭제
          </Button>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
        }}
      >
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            color: "#bbbbbb",
            marginLeft: "20px",
            marginRight: "40px",
            lineHeight: "35px",
          }}
        >
          <span>토큰 생성일</span>
          <span>토큰 만료일</span>
          <span>남은 기간</span>
          <span>JSON URL</span>
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            color: "white",
            // fontWeight: "bold",
            lineHeight: "35px",
          }}
        >
          <span>{apiTokenInfo.createdAt}</span>
          <span>{apiTokenInfo.expiredAt}</span>
          <span>{apiTokenInfo.leftDate}일</span>
          <div style={{ fontSize: "14px" }}>
            <span>
              https://sdilink.duckdns.org/api/insurance/api/bms?apiToken=
            </span>
            <span style={{ color: "#F1CFCF", fontWeight: "bold" }}>
              api토큰
            </span>
            <span>&startTime=</span>
            <span style={{ color: "#F1CFCF", fontWeight: "bold" }}>
              YYYY-MM-dd hh:mm
            </span>
            <span>&endTime=</span>
            <span style={{ color: "#F1CFCF", fontWeight: "bold" }}>
              YYYY-MM-dd hh:mm
            </span>
            <span>&carNumber=</span>
            <span style={{ color: "#F1CFCF", fontWeight: "bold" }}>차번호</span>
          </div>
        </div>
      </div>
    </div>
  ) : (
    <div
      style={{
        height: "15vh",
        backgroundColor: "#303030",
        padding: "10px",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "space-evenly",
      }}
    >
      <p
        style={{
          display: "flex",
          flexDirection: "column",
          color: "white",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        현재 발급되어 있는 토큰이 없습니다.
      </p>
      <Button
        variant="contained"
        style={{ backgroundColor: "#1428A0", marginRight: "20px" }}
        onClick={makeToken}
      >
        토큰 발급
      </Button>
    </div>
  );
}
