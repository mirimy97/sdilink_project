function GradientSVG() {
  const idCSS = "SOH";
  const gradientTransform = `rotate(90)`;
  return (
    <svg style={{ height: 0 }}>
      <defs>
        <linearGradient id={idCSS} gradientTransform={gradientTransform}>
          <stop offset="10%" stopColor="#6B8AEB" />
          <stop offset="85.56%" stopColor="#A36BFD" />
        </linearGradient>
      </defs>
    </svg>
  );
}

export default GradientSVG;
