import Box from "@mui/material/Box";
import Modal from "@mui/material/Modal";
import CloseIcon from "@mui/icons-material/Close";
import { useState } from "react";
import { User } from "../interfaces";
import Button from "@mui/material/Button";
import { useAppSelector, useAppDispatch } from "../redux/hooks";
import "./SearchUser.css";
import axiosApi from "../axiosApi";

interface Isearch {
  carId: number;
  carNumber: string;
  userName: string;
}
interface Ilist {
  acceptList: User[] | never;
  waitList: User[] | never;
  refuseList: User[] | never;
}

export function SearchUser({ acceptList, waitList, refuseList }: Ilist) {
  const [searchRes, setSearchRes] = useState<Isearch | null>(null);
  const [searchErr, setSearchErr] = useState(3);
  const accessToken = useAppSelector((store) => store.insurance.token);

  // input 관리
  const [inputs, setInputs] = useState({
    carUser: "",
    carNum: "",
  });
  const { carUser, carNum } = inputs;

  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // console.log(e.target.value, e.target.name);
    const { value, name } = e.target;
    setInputs({
      ...inputs,
      [name]: value,
    });
  };

  // 검색
  const search = () => {
    if (inputs.carUser && inputs.carNum) {
      axiosApi
        .post(
          "/insurance/search",
          {
            userName: carUser,
            carNumber: carNum,
          },
          {
            headers: {
              Authorization: accessToken,
            },
          }
        )
        .then((res) => {
          // console.log(res.data);
          if (res.data) {
            setSearchRes(res.data);
            setRequestState(false);

            for (const obj of acceptList) {
              if (obj.carId === res.data.carId) {
                // console.log("carId가 동일합니다.");
                setRequestState(true);
                setCompleteState(true);
                break; // 반복문을 빠져나옵니다.
              }
            }
            for (const obj of waitList) {
              if (obj.carId === res.data.carId) {
                // console.log("carId가 동일합니다.");
                setRequestState(true);
                // setCompleteState(false);
                break; // 반복문을 빠져나옵니다.
              }
            }
          }
        })
        .catch((err) => {
          setSearchRes(null);
          setSearchErr(err.response.status);
        });
    } else if (inputs.carUser === "" && inputs.carNum === "") {
      setSearchRes(null);
      setSearchErr(3);
    } else if (inputs.carUser === "") {
      setSearchRes(null);
      setSearchErr(1);
    } else {
      setSearchRes(null);
      setSearchErr(2);
    }
  };

  // 차량번호 엔터 시 검색 기능
  const handleKey = (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key === "Enter") {
      search();
    }
  };

  // 승인 요청 보내기 => 이후 중복 조회 요청 막기
  const [requestState, setRequestState] = useState(false);
  // 승인 완료 된 고객 분기
  const [completeState, setCompleteState] = useState(false);
  const onClickHandler = () => {
    axiosApi
      .post(
        `/insurance/approvals/cars/${searchRes?.carId}`,
        {},
        {
          headers: {
            Authorization: accessToken,
          },
          params: {
            car_id: searchRes?.carId,
          },
        }
      )
      .then((res) => {
        // console.log(res.data);
        setRequestState(true);
      })
      .catch((err) => setSearchErr(err.response.status));
  };

  return (
    <div
      style={{
        height: "20vh",
        backgroundColor: "#303030",
        padding: "20px 30px 10px 30px",
        position: "relative",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "15px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center" }}>
          <label htmlFor="carUser" className="searchLabel">
            차량 소유주명
          </label>
          <input
            type="text"
            id="carUser"
            name="carUser"
            className="searchInput"
            onChange={onChange}
            placeholder="차량 소유주명을 입력해주세요"
          />
          <label htmlFor="carNum" className="searchLabel">
            차량 번호
          </label>
          <input
            type="text"
            id="carNum"
            name="carNum"
            className="searchInput"
            onChange={onChange}
            onKeyDown={handleKey}
            placeholder="전체 차량 번호를 입력해주세요"
          />
        </div>
        <Button
          variant="contained"
          size="small"
          style={{
            border: "none",
            borderRadius: "3px",
            backgroundColor: "#1428A0",
          }}
          onClick={search}
        >
          검색
        </Button>
      </div>
      <div style={{ border: "1px solid #7F7F7F", marginBottom: "10px" }}></div>
      {searchRes === null ? (
        searchErr === 3 ? (
          <div className="err">
            차량 소유주명과 차량 전체 번호를 모두 입력하셔야 정보 조회가
            가능합니다.
          </div>
        ) : searchErr === 2 ? (
          <div className="err">차량 번호를 입력해주세요</div>
        ) : searchErr === 1 ? (
          <div className="err">차량 소유주명을 입력해주세요</div>
        ) : searchErr === 404 ? (
          <div className="err">일치하는 차량 정보가 없습니다.</div>
        ) : (
          <div className="err">검색 결과가 없습니다.</div>
        )
      ) : (
        <>
          <div style={{ display: "flex" }}>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                fontWeight: "bold",
                lineHeight: "40px",
                marginRight: "50px",
                color: "#BBBBBB",
              }}
            >
              <span>차량 소유주명</span>
              <span>차량 번호</span>
            </div>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                lineHeight: "40px",
                color: "white",
              }}
            >
              <span>{searchRes!.userName}</span>
              <span>{searchRes!.carNumber}</span>
            </div>
          </div>
          {requestState ? (
            completeState ? (
              <Button
                variant="contained"
                style={{
                  backgroundColor: "#7F7F7F",
                  position: "absolute",
                  bottom: "10px",
                  right: "30px",
                  cursor: "default",
                }}
                disableElevation
                disableRipple
              >
                승인 완료 고객
              </Button>
            ) : (
              <Button
                variant="contained"
                style={{
                  backgroundColor: "#7F7F7F",
                  position: "absolute",
                  bottom: "10px",
                  right: "30px",
                  cursor: "default",
                }}
                disableElevation
                disableRipple
              >
                정보 요청 대기
              </Button>
            )
          ) : (
            <Button
              variant="contained"
              style={{
                backgroundColor: "#1428A0",
                position: "absolute",
                bottom: "10px",
                right: "30px",
              }}
              onClick={onClickHandler}
            >
              정보 조회 요청
            </Button>
          )}
        </>
      )}
    </div>
  );
}
