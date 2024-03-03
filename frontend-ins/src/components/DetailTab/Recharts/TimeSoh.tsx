import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { SOHData } from "../../../interfaces";

export function TimeSoh({ SOHData }: { SOHData: SOHData[] | null }) {
  const formatLabel = (name: number) => `${name} cycle`;
  return (
    <ResponsiveContainer width="100%" height="90%">
      <AreaChart
        width={500}
        height={400}
        data={SOHData!}
        margin={{
          top: 30,
          right: 30,
          left: 0,
          bottom: 5,
        }}
      >
        {/* <CartesianGrid strokeDasharray="3 3" /> */}
        <XAxis dataKey="name" tick={{ display: "none" }} />
        <YAxis domain={[0.6, 1]} />
        <Tooltip labelFormatter={formatLabel} />
        <Area type="monotone" dataKey="SOH" stroke="#8884d8" fill="#8884d8" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
