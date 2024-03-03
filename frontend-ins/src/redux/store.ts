import { configureStore } from "@reduxjs/toolkit";
import insuranceReducer from "./insurance";
import detailReducer from "./detail";
import storage from "redux-persist/lib/storage";
import { persistReducer } from "redux-persist";
import { combineReducers } from "redux";

const persistConfig = {
  key: "root",
  storage,
  whitelist: ["insurance"],
};

const rootReducer = combineReducers({
  insurance: insuranceReducer,
  detail: detailReducer,
});

const persistedReducer = persistReducer(persistConfig, rootReducer);

const store = configureStore({
  reducer: persistedReducer,
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export default store;
