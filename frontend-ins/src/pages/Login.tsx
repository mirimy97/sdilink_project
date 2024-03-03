import Button from "@mui/material/Button";
import { useState } from "react";
import TextField from "@mui/material/TextField";
import styled from "styled-components";
import axiosApi from "../axiosApi";
import { useAppDispatch } from "../redux/hooks";
import { getToken, loginIns } from "../redux/insurance";
import { useNavigate } from "react-router-dom";

export const LightTextField = styled(TextField)`
  & .MuiInputBase-input {
    color: #d9d9d9;
  }
  & label {
    color: #bbbbbb;
  }
  & label.Mui-focused {
    color: #167bff;
  }
  & .MuiOutlinedInput-root {
    & fieldset {
      border-color: #bbbbbb;
    }
    &:hover fieldset {
      border-color: #bbbbbb;
    }
    &.Mui-focused fieldset {
      border-color: #167bff;
    }
  }
  & .MuiFormHelperText-root {
    color: red !important;
  }
`;

export function Login() {
  // console.log(useAppSelector((store) => store.insurance.authenticated));
  // input 관리
  const [login, setLogin] = useState({
    insId: "",
    insPw: "",
  });

  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { value, name } = e.target;
    setLogin({
      ...login,
      [name]: value,
    });
  };

  // login axios 요청
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [errStatus, setErrStatus] = useState<number | null>(null);
  const loginRequest = () => {
    axiosApi
      .post("/insurance/login", {
        id: login.insId,
        password: login.insPw,
      })
      .then((res) => {
        const accessToken = res.headers?.authorization;
        dispatch(getToken(accessToken));
        dispatch(loginIns(res.data));
        navigate("/mypage");
      })
      .catch((err) => {
        // console.log(err.response.data);
        setErrStatus(err.response.data.status);
      });
  };

  // 비밀번호 엔터시 로그인 요청
  const handleKey = (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key === "Enter") {
      loginRequest();
    }
  };

  return (
    <div style={{ width: "100%", height: "100%", display: "flex" }}>
      <div
        style={{
          backgroundColor: "#303030",
          width: "60%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <img
          src="/assets/SDILink(2).png"
          alt="로고"
          width="50%"
          style={{ marginBottom: "-50px" }}
        />
      </div>

      {/* 로그인 폼 */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          width: "40%",
          backgroundColor: "white",
        }}
      >
        <div
          style={{
            fontWeight: "bold",
            fontSize: "26px",
            marginBottom: "20px",
            color: "#167BFF",
          }}
        >
          로그인
        </div>
        <div style={{ display: "flex", flexDirection: "column", width: "50%" }}>
          <TextField
            required
            error={errStatus === (404 || 1 || 2) ? true : false}
            id="insId"
            label="아이디"
            name="insId"
            onChange={onChange}
            placeholder="아이디를 입력하세요"
            helperText={errStatus === 404 ? "존재하지 않는 아이디입니다." : ""}
            size="small"
            style={{ marginBottom: "20px" }}
          />
          <TextField
            required
            error={errStatus === 403 ? true : false}
            type="password"
            id="password"
            label="비밀번호"
            name="insPw"
            onChange={onChange}
            placeholder="비밀번호를 입력하세요"
            helperText={
              errStatus === 403 ? "비밀번호가 일치하지 않습니다." : ""
            }
            size="small"
            style={{ marginBottom: "20px" }}
            onKeyDown={handleKey}
          />
          <Button
            variant="contained"
            style={{ backgroundColor: "#167BFF", fontWeight: "bold" }}
            onClick={loginRequest}
          >
            로그인
          </Button>
          <div
            style={{
              color: "#167BFF",
              fontSize: "10px",
              fontWeight: "bold",
              textAlign: "end",
              marginTop: "16px",
            }}
          >
            *회원가입은 관리자에게 문의해주시길 바랍니다.
          </div>
        </div>
      </div>
    </div>
  );
}
