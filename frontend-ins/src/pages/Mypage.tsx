import { Header } from "../components/Header";
import { useState, useEffect } from "react";
import { useAppSelector, useAppDispatch } from "../redux/hooks";
import { CustomList } from "../components/CustomList";
import "./Mypage.css";
import { SearchUser } from "../components/SearchUser";
import { TokenManage } from "../components/TokenManage";
import { Footer } from "../components/Footer";
import { RecentListItem } from "../components/RecentLIstItem";
import { RecentUser } from "../interfaces";
import { ScrollMenu } from "react-horizontal-scrolling-menu";
import "react-horizontal-scrolling-menu/dist/styles.css";
import styled from "styled-components";
import { logoutIns } from "../redux/insurance";
import axiosApi from "../axiosApi";
import { User } from "../interfaces";
import { useNavigate } from "react-router-dom";

export function Mypage() {
  const [loading, setLoading] = useState(true);
  const accessToken = useAppSelector((store) => store.insurance.token);
  const navigate = useNavigate();

  // 최근 조회 고객
  const [recentUserList, setRecentUserList] = useState<RecentUser[] | never>(
    []
  );
  // 고객 관리
  const [acceptList, setAcceptList] = useState<User[] | never>([]);
  const [waitList, setWaitList] = useState<User[] | never>([]);
  const [refuseList, setRefuseList] = useState<User[] | never>([]);

  // token 조회
  const checkToken = () => {
    axiosApi
      .get("/insurance/api/token", {
        headers: {
          Authorization: accessToken,
        },
      })
      .then((res) => {
        setApiTokenInfo(res.data);
        setIsToken(true);
      })
      .catch((err) => {
        console.log(err.response.status);
        setIsToken(false);
      });
  };

  // 승인 요청 보내기
  const dispatch = useAppDispatch();

  useEffect(() => {
    // api 조회
    if (accessToken) {
      Promise.all([
        axiosApi.get("/insurance/approvals/histories", {
          headers: {
            Authorization: accessToken,
          },
        }),
        axiosApi.get("/insurance/approvals", {
          headers: {
            Authorization: accessToken,
          },
        }),
        axiosApi.get("/insurance/api/token", {
          headers: {
            Authorization: accessToken,
          },
        }),
      ])
        .then(([res1, res2, res3]) => {
          // console.log(res1.data);
          setRecentUserList(res1.data);
          // console.log(res2.data);
          setAcceptList(res2.data.accept);
          setWaitList(res2.data.waiting);
          setRefuseList(res2.data.refuse);
          setApiTokenInfo(res3.data);
          setIsToken(true);

          setLoading(false);
        })
        .catch((err) => {
          console.log(err);
          if (err.response.data.status === 401 || 403) {
            dispatch(logoutIns());
            navigate("/login");
          }
        });
    } else {
      navigate("/login");
    }
  }, []);

  // 토큰 관리
  const [isToken, setIsToken] = useState<boolean>(false);
  const [apiTokenInfo, setApiTokenInfo] = useState({
    apiToken: "",
    createdAt: "",
    expiredAt: "",
    leftDate: 0,
  });

  // 승인 요청 보내기
  const onClickHandler = (carId: number) => {
    axiosApi
      .post(
        `/insurance/approvals/cars/${carId}`,
        {},
        {
          headers: {
            Authorization: accessToken,
          },
          params: {
            car_id: carId,
          },
        }
      )
      // .then((res) => console.log(res.data))
      .catch((err) => console.log(err.response.status));
  };

  return loading ? (
    <></>
  ) : (
    <div>
      <Header />
      <div className="mainTitle">최근 조회 목록</div>
      <div style={{ display: "flex" }}>
        <RecentContainer>
          <ScrollMenu>
            {recentUserList &&
              recentUserList.map((item, i) => (
                <RecentListItem key={i} item={item} />
              ))}
          </ScrollMenu>
        </RecentContainer>
      </div>

      <div className="mainTitle">고객 검색</div>
      <SearchUser
        acceptList={acceptList}
        waitList={waitList}
        refuseList={refuseList}
      />
      <div className="mainTitle">고객 관리</div>
      <CustomList
        acceptList={acceptList}
        waitList={waitList}
        refuseList={refuseList}
        onClickHandler={onClickHandler}
      />
      <div className="mainTitle">토큰 관리</div>
      <TokenManage
        isToken={isToken}
        setIsToken={setIsToken}
        apiTokenInfo={apiTokenInfo}
        checkToken={checkToken}
      />
      <Footer />
    </div>
  );
}

const RecentContainer = styled.div`
  overflow: hidden;

  .react-horizontal-scrolling-menu--scroll-container {
    -ms-overflow-style: none; /* IE and Edge */
    scrollbar-width: none; /* Firefox */
  }
`;
