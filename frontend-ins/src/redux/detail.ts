import { createSlice } from "@reduxjs/toolkit";

export const detailSlice = createSlice({
  name: "detail",
  initialState: {
    approvalId: "",
    userName: "",
    carUniqueId: "", // 차종
    carNum: "",
    birth: "",
    carInfoId: "",
    modelName: "",
    packCode: "",
    // batteryCode: "", // 배터리 팩, 모듈, 셀 각각 일련번호 존재
  },
  reducers: {
    goToDetail: (state, action) => {
      state.approvalId = action.payload.id;
      state.userName = action.payload.name;
      state.carUniqueId = action.payload.carId; // 상세페이지 이동시 필요한 unique key
      state.carNum = action.payload.carNumber;
      return state;
    },
    carDetailInfo: (state, action) => {
      state.userName = action.payload.name;
      state.carInfoId = action.payload.carInfoId;
      state.modelName = action.payload.modelName;
      state.carNum = action.payload.carNumber;
      state.packCode = action.payload.packCode;
      state.birth = action.payload.birth;
    },
  },
});

export const { goToDetail, carDetailInfo } = detailSlice.actions;
export default detailSlice.reducer;
