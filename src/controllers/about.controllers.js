const getAboutPage = ((req, res) => {
    res
        .status(200)
        .send("WorkDen is a collaborative tool that enables teams to work with ease.");
});
export { getAboutPage };