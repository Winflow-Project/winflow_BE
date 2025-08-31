import fs from 'fs';
import path from 'path';
// import mime from 'mime-types';
import Config from '@config/dotenv.config';
import { v2 as cloudinary } from 'cloudinary';
import {
  Timeout,
  ServerError,
  BadRequest,
} from '@middlewares/error.middleware';

cloudinary.config({
  api_key: Config.Cloud.key,
  api_secret: Config.Cloud.secret,
  cloud_name: Config.Cloud.name,
});

export const uploadToCloudinary = async (fileToUpload: string) => {
  try {
    const data = await cloudinary.uploader.upload(fileToUpload, {
      resource_type: 'auto',
    });
    deleteFromDiskStorage(fileToUpload);
    // console.log('upload data:', data);
    return data;
  } catch (error: unknown) {
    deleteFromDiskStorage(fileToUpload);
    const cloudinaryErr = error as Error;
    if (cloudinaryErr.name === 'TimeoutError') {
      throw new Timeout('Request Timeout, please try again');
    }
    throw new ServerError(`Error occured (cloudinary), ${cloudinaryErr}`);
  }
};

export const uploadMultipleToCloudinary = async (filesToUpload: string[]) => {
  try {
    const uploadPromises = filesToUpload.map((file) =>
      cloudinary.uploader.upload(file, {
        resource_type: 'auto',
      })
    );

    const uploadResults = await Promise.all(uploadPromises);
    console.log('uploaded results', uploadResults);

    // Cleanup all uploaded files from disk storage
    filesToUpload.forEach(deleteFromDiskStorage);

    console.log('upload results:', uploadResults);
    return uploadResults;
  } catch (error: unknown) {
    // Cleanup files in case of error
    filesToUpload.forEach(deleteFromDiskStorage);

    const cloudinaryErr = error as Error;
    if (cloudinaryErr.name === 'TimeoutError') {
      throw new Timeout('Request Timeout, please try again');
    }
    throw new ServerError(
      `Error occurred (cloudinary), ${cloudinaryErr.message}`
    );
  }
};

export const deleteFromCloudinary = async (publicId: string) => {
  try {
    const result = await cloudinary.uploader.destroy(publicId);
    return result;
  } catch (error: unknown) {
    const cloudinaryErr = error as Error;
    throw new ServerError(
      `Internal Server Error (cloudinary deletion), ${cloudinaryErr.message}`
    );
  }
};

export const deleteMultipleFromCloudinary = async (publicIds: string[]) => {
  try {
    const result = await cloudinary.api.delete_resources(publicIds);
    return result;
  } catch (error) {
    return error;
  }
};

const deleteFromDiskStorage = (filePath: string) => {
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    // httpLogger.error(`Error occured (disk), ${error}`);
  }
};
