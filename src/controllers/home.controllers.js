const getHomePage = ((req, res) => {
    res
        .status(200)
        .send("Welcome to WorkDen!");
});
export { getHomePage };