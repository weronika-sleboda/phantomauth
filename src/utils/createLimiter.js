
export const createLimiter = (opts, FlexLimiterRef) => {
  return new FlexLimiterRef(opts);
}