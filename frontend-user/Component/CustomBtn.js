import { View } from "react-native";
import { Text } from "react-native-paper";
import { theme } from "../colors";
import React, { useEffect, useState } from "react";
import axiosAPI from "../api/axiosAPI";
import { TouchableOpacity } from "react-native-gesture-handler";

export default function CustomBtn({ aid, isA, title, history, setHistory }) {
  const handleApprove = async (aid, isA) => {
    try {
      await axiosAPI.post("/client/approvals", {
        id: aid, // 승인 id
        isApprove: isA, //  1 : 승인 확인, 2 : 승인거절
      });
      const updatedHistory = history.map((his) => {
        if (his.approvalId === aid) {
          return { ...his, isApprove: isA };
        }
        return his;
      });
      setHistory(updatedHistory);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <TouchableOpacity
      onPressIn={() => handleApprove(aid, isA)}
      // onPress={onPress}
      rippleColor={theme.primary}
      style={{ marginRight: 5 }}
    >
      <View
        style={{
          paddingHorizontal: 10,
          paddingVertical: 6,
          borderRadius: 10,
          backgroundColor: title === "열람 거절" ? theme.blue0 : theme.blue,
        }}
      >
        <Text
          style={{
            fontSize: 11,
            color: title === "열람 거절" ? theme.blue : theme.white,
          }}
        >
          {title}
        </Text>
      </View>
    </TouchableOpacity>
  );
}
