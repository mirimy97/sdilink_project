export interface User {
  id: number;
  userName: string;
  insuranceName: string;
  carId?: number;
  carNumber: string;
  createdAt: string; // 정보조회 요청 날짜
  authTime?: string; // 승인 날짜
  endTime?: string; // 정보조회 만료 날짜
  refuseTime?: string;
  leftDay?: number;
}

export interface UserDetail {
  id: number;
  userName: string;
  birth: string;
  carId: string;
  carNumber: string;
}

export interface RecentUser {
  viewHistoryId: number;
  approvalId: number;
  carId: number;
  name: string;
  carInfoId: number;
  modelName: string;
  packCode: string;
  createdAt: string;
  isExpired: boolean;
}

export interface Token {
  apiToken: string;
  tokenDate: string;
  tokenEndDate: string;
  remainingDate: number;
}

export interface CarBasicInfo {
  batteryCapacity: number;
  batteryKind: string;
  distance: number;
  drivingMethod: string;
  efficiency: number;
  id: number;
  maker: string;
  modelName: string;
  peopleCapacity: number;
}

export interface ModuleCellsMapping {
  [key: string]: string[];
}

export interface UserDetailInfo {
  name: string;
  birth: string;
  carInfoId: number;
  modelName: string;
  carNumber: string;
  packCode: string;
}

export interface AnalysisInfo {
  fastCharge: number; //    급속충전횟수
  slowCharge: number; //    완속충전횟수
  totalRuntime: number; //    배터리 동작시간(초)
  totalCycle: number; //    누적 싸이클
  totalCharge: number; //    누적 충전량
  totalDischarge: number; //    누적 방전량
  bleftCycle: number; //    배터리교체예상시기 (남은 사이클)
  totalDrive: number; //    누적 주행거리(km)
  btotalScore: number; //    배터리성능상태(전체 100점)
}

export interface PackInfo {
  capacity: number;
  createdAt: string;
  current: number;
  cycle: number;
  id: number;
  packCode: string;
  soc: number;
  soh: number;
  status: string;
  voltageP: number;
  tempP: number;
}

export interface Props {
  startDateString: string;
  // EndDateString: string;
  // endTimeString: string;
  startTimeString: string;
  approvalId: string;
  accessToken: string;
  nowTime: string | null;
}

export interface ModuleInfo {
  id: number;
  moduleCode: string;
  temp: number;
  voltage: number;
  createdAt: string;
  outlier: number;
}

export interface CellInfo {
  id: number;
  cellCode: string;
  voltageC: number;
  outlier: number;
  isNormal: number;
  createdAt: string;
}

export interface CellLogData {
  id: number;
  cellCode: string;
  voltageC: number;
  outlier: number;
  isNormal: number;
  createdAt: string;
}

export interface NowBMSData {
  id: number;
  moduleCode: string;
  temp: number;
  voltage: number;
  cellLogList: CellLogData[];
}

export interface SOHData {
  name: string;
  SOH: number;
}

export interface BMSChartData {
  name: string;
  voltageP: number;
  current: number;
  tempP: number;
}

export interface csvPack {
  packNum: string;
  voltageP: number;
  current: number;
  tempP: number;
  status: string;
  SOC: number;
  SOH: number;
  cycle: number;
  createdAt: string;
}

export interface csvModule {
  packNum: string;
  moduleNum: string;
  voltageM: number;
  tempM: number;
  outlier: number;
  createdAt: string;
}

export interface csvCell {
  packNum: string;
  moduleNum: string;
  cellNum: string;
  voltageC: number;
  outlier: number;
  createdAt: string;
}
