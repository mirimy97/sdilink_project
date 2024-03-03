import AsyncStorage from "@react-native-async-storage/async-storage";
import axios from "axios";

const axiosAPI = axios.create({
  baseURL: "https://k8e101.p.ssafy.io/api",
});

axiosAPI.interceptors.request.use(
  async (config) => {
    const token = await AsyncStorage.getItem("userToken");
    // console.log(token);
    // config.headers["Content-Type"] = "application/json; charset=utf-8";
    if (token) {
      config.headers.Authorization = `${token}`;
    }
    return config;
  },
  (err) => {
    return Promise.reject(err);
  }
);

axiosAPI.interceptors.response.use(
  async (response) => {
    const token = response.headers["Authorization"];

    // 토큰이 포함된 header가 없는 경우
    if (!token) {
      return response;
    }

    // AsyncStorage에 토큰을 저장합니다.
    try {
      await AsyncStorage.setItem("userToken", token);
    } catch (error) {
      console.log(error);
    }

    return response;
  },
  (error) => {
    return Promise.reject(error);
  }
);
export default axiosAPI;
