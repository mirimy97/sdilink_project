export function ProgressBar({ ratio }: { ratio: number }) {
  const containerStyles = {
    height: 24,
    width: "80%",
    backgroundColor: "#bbbbbb",
    borderRadius: 5,
    marginLeft: 30,
  };

  const fillerStyles = {
    height: "100%",
    width: `${ratio}%`,
    borderRadius: "inherit",
    background: `linear-gradient(to right, #A36BFD, #6B8AEB)`,
    // background: `linear-gradient(to right, #A36BFD 0%, #6B8AEB 50%, #167BFF 100%)`,
  };

  const labelStyles = {
    padding: 10,
    color: "white",
    // fontWeight: "bold",
  };

  return (
    <div style={containerStyles}>
      <div style={fillerStyles}>
        <span style={labelStyles}>{`${ratio.toFixed(4)}%`}</span>
      </div>
    </div>
  );
}
