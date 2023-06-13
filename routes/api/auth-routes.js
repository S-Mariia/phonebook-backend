const express = require("express");

const ctrl = require("../../controllers/auth-controllers");

const { schemas } = require("../../models/user");

const { validateBody, authenticate, upload } = require("../../middlewares");

const router = express.Router();

router.post("/signup", validateBody(schemas.registerSchema), ctrl.register);
router.post("/login", validateBody(schemas.loginSchema), ctrl.login);
router.post("/logout", authenticate, ctrl.logout);
router.get("/current", authenticate, ctrl.getCurrentUser);
router.patch(
  "/avatars",
  authenticate,
  upload.single("avatarURL"),
  ctrl.updateAvatar
);

module.exports = router;
