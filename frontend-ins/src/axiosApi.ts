import axios from "axios";

const axiosApi = axios.create({ baseURL: "https://k8e101.p.ssafy.io/api" });
// axiosApi.defaults.xsrfCookieName = "csrftoken";
// axiosApi.defaults.xsrfHeaderName = "X-CSRFTOKEN";

export default axiosApi;
