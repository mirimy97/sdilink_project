import { createSlice } from "@reduxjs/toolkit";

export const insuranceSlice = createSlice({
  name: "insurance",
  initialState: {
    authenticated: false,
    token: "",
    name: "",
    imgSrc: "",
    loginDate: "",
  },
  reducers: {
    getToken: (state, action) => {
      state.authenticated = true;
      state.token = action.payload;
    },
    loginIns: (state, action) => {
      state.name = action.payload.name;
      state.imgSrc = action.payload.imgSrc;
      state.loginDate = action.payload.loginDate;
      return state;
    },
    logoutIns: (state) => {
      state.authenticated = false;
      state.token = "";
      state.name = "";
      state.imgSrc = "";
      state.loginDate = "";
      return state;
    },
  },
});

export const { getToken, loginIns, logoutIns } = insuranceSlice.actions;
export default insuranceSlice.reducer;
