import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDTO } from './dto/createUser.dto';
import { User } from './model/User';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginUserDTO } from './dto/loginUser.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './model/RefreshToken';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken } from './model/ResetToken';
import { MailService } from 'src/services/mail.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name) private resetTokenModel: Model<ResetToken>,
    private jwt: JwtService,
    private mailService: MailService
  ) {}

  async generateUserToken(
    userId,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = { userId };
    const accessToken = this.jwt.sign(payload, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);
    return { accessToken, refreshToken };
  }

  async storeRefreshToken(token: string, userId) {
    // Calculate expiry date 3 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    // Find the user by userId and update the refresh token to
    // previous expiry date + 3 days and the new token
    await this.refreshTokenModel.updateOne({ userId },{ $set: { expiryDate, token}},{ upsert: true });
  }

  async refreshTokens(refreshToken: string) {
    // Verify this refresh token exists in our database
    // and has not yet expired
    const token = await this.refreshTokenModel.findOneAndDelete({ token: refreshToken, expiryDate: {$gte: new Date()}});
    if(!token) throw new UnauthorizedException("Please login again");
    // Extract userId from refresh token and generate a new refresh token
    return this.generateUserToken(token.userId);
  }

  async signup(userDetails: CreateUserDTO) {
    // Check if email is in use
    const user = await this.userModel.findOne({ email: userDetails.email });
    if (user)
      throw new BadRequestException('User with this email already exists');
    // Hash Password
    const hashedPassword = await bcrypt.hash(userDetails.password, 10);
    // Create user document and save in MongoDB
    await this.userModel.create({ ...userDetails, password: hashedPassword });
  }

  async login(userDetails: LoginUserDTO) {
    // Check if user with this email exists
    const user = await this.userModel.findOne({ email: userDetails.email });
    if (!user) throw new UnauthorizedException('Credentials invalid');
    // Compare entered password with database password
    const isMatched = await bcrypt.compare(userDetails.password, user.password);
    if (!isMatched) throw new UnauthorizedException('Credentials invalid');
    // Generate JWT token & Refresh token
    const tokens = await this.generateUserToken(user._id);
    return{
        ...tokens,
        userId: user._id
    }
  }

  async changePassword(userId, oldPassword: string, newPassword: string){
    // Find the user
    const user = await this.userModel.findOne({_id: userId});
    if(!user) throw new NotFoundException("Please login again");
    // Compare the old password with the new password in DB
    const isMatched = await bcrypt.compare(oldPassword,user.password);
    if(!isMatched) throw new UnauthorizedException("Credentials invalid");
    if(oldPassword===newPassword) throw new BadRequestException("Old and New passwords cannot be same");
    // Change user's password after hashing it
    const hashedPassword = await bcrypt.hash(newPassword,10);
    await this.userModel.findByIdAndUpdate(userId,{password: hashedPassword});
  }

  async forgotPassword(email: string){
    // Find the user with given email
    const user = await this.userModel.findOne({email});
    if(!user) throw new NotFoundException("No user with such email found");
    // Generate random 64 character reset token and
    // set expiry date to 1 hour later
    const resetToken = nanoid(64);
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1);
    await this.resetTokenModel.create({
      token: resetToken,
      userId: user._id,
      expiryDate
    })
    // Send the link to the user by email (nodemailer)
    this.mailService.sendPasswordResetEmail(email,resetToken);
    return {message: 'Reset password email sent successfully'};
  }

  async resetPassword(resetToken: string, newPassword: string){
    // Find the user with reset Token and expiry date greater 
    // than current date
    const token = await this.resetTokenModel.findOneAndDelete({ token: resetToken, expiryDate: {$gte: new Date()}});
    if(!token) throw new UnauthorizedException("Invalid link");
    // Change user password after hashing it
    const hashedPassword = await bcrypt.hash(newPassword,10);
    await this.userModel.findByIdAndUpdate(token._id,{password: hashedPassword});
  }
}
