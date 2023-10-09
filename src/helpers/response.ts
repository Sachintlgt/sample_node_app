import utility from "./utility";

const responseCode = {
    // General error code
    'GEN0000': {
        code: 'GEN0000',
        msg: ""
    },
    'GEN0001': {
        code: 'GEN0001',
        msg: "Invalid API call"
    },
    'GEN0002': {
        code: 'GEN0002',
        msg: "Invalid or unauthorised user"
    },
    'GEN0003': {
        code: 'GEN0003',
        msg: 'Validation error'
    },
    'GEN0004': {
        code: 'GEN0004',
        msg: 'Something went wrong'
    },
    'GEN0005': {
        code: 'GEN0005',
        msg: 'Unauthorised access'
    },
    'GEN0006': {
        code: 'GEN0006',
        msg: 'Data updated successfully'
    },
    'GEN0007': {
        code: 'GEN0007',
        msg: 'Action failed'
    },
    'GEN0008': {
        code: 'GEN0008',
        msg: 'List of data displayed successfully'
    },
    'GEN0009': {
        code: 'GEN0009',
        msg: 'Record not found'
    },
    'GEN0010': {
        code: 'GEN0010',
        msg: 'Error Occurred While Uploading Image'
    },
    'GEN0011': {
        code: 'GEN0011',
        msg: 'Activity log display Successfully'
    },
    'GEN0012': {
        code: 'GEN0012',
        msg: 'Data not found.'
    },
    'GEN0013': {
        code: 'GEN0013',
        msg: 'File uploaded Successfully.'
    },
    'GEN0014': {
        code: 'GEN0014',
        msg: 'Error Occurred While Uploading file'
    },
    'GEN0015': {
        code: 'GEN0015',
        msg: 'Attached file not found, please try again'
    },
    'GEN0016': {
        code: 'GEN0016',
        msg: 'You Are Trying To Upload Empty File. Please try again later'
    },
    'GEN0017': {
        code: 'GEN0017',
        msg: 'Field(s) are missing in the file uploaded'
    },
    'GEN0018': {
        code: 'GEN0018',
        msg: 'Incorrect data format for value'
    },
    'GEN0019': {
        code: 'GEN0019',
        msg: 'Invalid file data.'
    },
    'GEN0020': {
        code: 'GEN0020',
        msg: 'Records already exists.'
    },


    // validation error code
    'VAL0001': {
        code: 'VAL0001',
        msg: 'Email already exist'
    },
    'VAL0002': {
        code: 'VAL0002',
        msg: 'Current and New Password should not be same'
    },
    'VAL0003': {
        code: 'VAL0003',
        msg: 'New and Confirm Password should be same'
    },
    'VAL0004': {
        code: 'VAL0004',
        msg: 'Invalid user'
    },
    'VAL0005': {
        code: 'VAL0005',
        msg: 'Invalid current password'
    },
    'VAL0006': {
        code: 'VAL0006',
        msg: 'User profile is not activated'
    },
    'VAL0007': {
        code: 'VAL0007',
        msg: 'Invalid food category'
    },
    'VAL0008': {
        code: 'VAL0008',
        msg: 'Invalid source id'
    },
    'VAL0009': {
        code: 'VAL0009',
        msg: 'This product name already in use'
    },
    'VAL0010': {
        code: 'VAL0010',
        msg: 'Current password & New password should not be same.'
    },
    'VAL0011': {
        code: 'VAL0011',
        msg: 'Invalid Product Additive Replacement'
    },
    'VAL0012': {
        code: 'VAL0012',
        msg: 'Invalid Field Data'
    },
    'VAL0013': {
        code: 'VAL0013',
        msg: 'Records Already exists'
    },


    // auth error code
    'AUTH0001': {
        code: 'AUTH0001',
        msg: 'User created successfully'
    },
    'AUTH0002': {
        code: 'AUTH0002',
        msg: 'Failed to create user'
    },
    'AUTH0003': {
        code: 'AUTH0003',
        msg: 'Invalid role id'
    },
    'AUTH0004': {
        code: 'AUTH0004',
        msg: 'Role already assigned to this user'
    },
    'AUTH0005': {
        code: 'AUTH0005',
        msg: 'Invalid login id'
    },
    'AUTH0006': {
        code: 'AUTH0006',
        msg: 'Invalid password'
    },
    'AUTH0007': {
        code: 'AUTH0007',
        msg: 'Login successfully'
    },
    'AUTH0008': {
        code: 'AUTH0008',
        msg: 'Invalid Email id'
    },
    'AUTH0009': {
        code: 'AUTH0009',
        msg: 'Password updated successfully'
    },
    'AUTH0010': {
        code: 'AUTH0010',
        msg: 'Profile updated successfully'
    },
    'AUTH0011': {
        code: 'AUTH0011',
        msg: 'Status updated successfully'
    },
    'AUTH0012': {
        code: 'AUTH0012',
        msg: 'User deleted successfully'
    },
    'AUTH0013': {
        code: 'AUTH0013',
        msg: 'Get user detail successfully'
    },
    'AUTH0014': {
        code: 'AUTH0014',
        msg: 'Get user list successfully'
    },
    'AUTH0015': {
        code: 'AUTH0015',
        msg: 'OTP verified successfully'
    },
    'AUTH0016': {
        code: 'AUTH0016',
        msg: 'OTP sent successfully'
    },
    'AUTH0017': {
        code: 'AUTH0017',
        msg: 'Invalid/Expired OTP'
    },
    'AUTH0018': {
        code: 'AUTH0018',
        msg: 'Error occurred while generating OTP'
    },
    'AUTH0019': {
        code: 'AUTH0019',
        msg: 'Email sent successfully'
    },

    'USER0001': {
        code: 'USER0001',
        msg: 'user roles count display successfully'
    },
    'USER0002': {
        code: 'USER0002',
        msg: 'Filters list display Successfully'
    },
    'USER0003': {
        code: 'USER0003',
        msg: 'Roles list display Successfully'
    },
    'USER0004': {
        code: 'USER0004',
        msg: 'Users list display Successfully'
    },
    'USER0005': {
        code: 'USER0005',
        msg: 'Users status updated Successfully'
    },
    'USER0006': {
        code: 'USER0006',
        msg: 'Users is not exist'
    },
    'USER0007': {
        code: 'USER0007',
        msg: 'Users already exist'
    },


    // Plant error code
    'PLANT0001': {
        code: 'PLANT0001',
        msg: 'Plant saved successfully'
    },
    'PLANT0002': {
        code: 'PLANT0002',
        msg: 'Action failed'
    },
    'PLANT0003': {
        code: 'PLANT0003',
        msg: 'Plant updated successfully'
    },
    'PLANT0004': {
        code: 'PLANT0004',
        msg: 'Get plant detail successfully'
    },
    'PLANT0005': {
        code: 'PLANT0005',
        msg: 'Plant list displayed successfully'
    },
    'PLANT0006': {
        code: 'PLANT0006',
        msg: 'Plant tasks updated successfully'
    },
    'PLANT0007': {
        code: 'PLANT0007',
        msg: 'Invalid plant Id'
    },
    'PLANT0008': {
        code: 'PLANT0008',
        msg: 'Invalid stage Id'
    },
    'PLANT0009': {
        code: 'PLANT0009',
        msg: 'Plant task deleted successfully'
    },
    'PLANT0010': {
        code: 'PLANT0010',
        msg: 'Plant functionalities saved successfully'
    },
    'PLANT0011': {
        code: 'PLANT0011',
        msg: 'Invalid functionality'
    },
    'PLANT0012': {
        code: 'PLANT0012',
        msg: 'Plant functionalities updated successfully'
    },
    'PLANT0013': {
        code: 'PLANT0013',
        msg: 'Plant functionalities list displayed successfully'
    },
    'PLANT0014': {
        code: 'PLANT0014',
        msg: 'Plant functionalities detail displayed successfully'
    },
    'PLANT0015': {
        code: 'PLANT0015',
        msg: 'Plant functionalities deleted successfully'
    },
    'PLANT0016': {
        code: 'PLANT0016',
        msg: 'Plant images uploaded successfully'
    },
    'PLANT0017': {
        code: 'PLANT0017',
        msg: 'Invalid image upload'
    },
    'PLANT0018': {
        code: 'PLANT0018',
        msg: 'Error occurred while uploading file'
    },
    'PLANT0019': {
        code: 'PLANT0019',
        msg: 'Plant image deleted successfully'
    },
    'PLANT0020': {
        code: 'PLANT0020',
        msg: 'Plants images list displayed successfully'
    },
    'PLANT0021': {
        code: 'PLANT0021',
        msg: 'Plants images detail displayed successfully'
    },
    'PLANT0022': {
        code: 'PLANT0022',
        msg: 'Plants physico detail displayed successfully'
    },
    'PLANT0023': {
        code: 'PLANT0023',
        msg: 'Plants nutritional information detail displayed successfully'
    },
    'PLANT0024': {
        code: 'PLANT0024',
        msg: 'Plants organoleptic detail displayed successfully'
    },
    'PLANT0025': {
        code: 'PLANT0025',
        msg: 'Plants product categories saved  successfully'
    },
    'PLANT0026': {
        code: 'PLANT0026',
        msg: 'Invalid product category id'
    },
    'PLANT0027': {
        code: 'PLANT0027',
        msg: 'Plants product categories displayed successfully'
    },
    'PLANT0028': {
        code: 'PLANT0028',
        msg: 'Plant product categories deleted successfully'
    },
    'PLANT0029': {
        code: 'PLANT0029',
        msg: 'Plant food categories saved successfully'
    },
    'PLANT0030': {
        code: 'PLANT0030',
        msg: 'Plant food categories displayed successfully'
    },
    'PLANT0031': {
        code: 'PLANT0031',
        msg: 'Plant food categories deleted successfully'
    },
    'PLANT0032': {
        code: 'PLANT0032',
        msg: 'Invalid plant parts id'
    },
    'PLANT0033': {
        code: 'PLANT0033',
        msg: 'Plant count displayed successfully'
    },
    'PLANT0034': {
        code: 'PLANT0034',
        msg: 'Plant source list displayed successfully'
    },
    'PLANT0035': {
        code: 'PLANT0035',
        msg: 'Plant status list displayed successfully'
    },
    'PLANT0036': {
        code: 'PLANT0036',
        msg: 'Assigned from list displayed successfully'
    },
    'PLANT0037': {
        code: 'PLANT0037',
        msg: 'Plants toxicology detail displayed successfully'
    },
    'PLANT0038': {
        code: 'PLANT0038',
        msg: 'Plants sustainability detail displayed successfully'
    },
    'PLANT0039': {
        code: 'PLANT0039',
        msg: 'Plants ayurveda detail displayed successfully'
    },
    'PLANT0040': {
        code: 'PLANT0039',
        msg: 'Filters list displayed successfully'
    },
    'PLANT0041': {
        code: 'PLANT0041',
        msg: 'Functionalities list displayed successfully'
    },
    'PLANT0042': {
        code: 'PLANT0042',
        msg: 'Set default plant image successfully'
    },
    'PLANT0043': {
        code: 'PLANT0043',
        msg: 'Invalid plant image id.'
    },
    'PLANT0044': {
        code: 'PLANT0044',
        msg: 'Plant extraction saved successfully'
    },
    'PLANT0045': {
        code: 'PLANT0045',
        msg: 'Invalid form id'
    },
    'PLANT0046': {
        code: 'PLANT0046',
        msg: 'Form list displayed successfully'
    },
    'PLANT0047': {
        code: 'PLANT0047',
        msg: 'Plants properties displayed successfully'
    },
    'PLANT0048': {
        code: 'PLANT0048',
        msg: 'Plants parts list displayed successfully'
    },
    'PLANT0049': {
        code: 'PLANT0048',
        msg: 'Plants extraction list displayed successfully'
    },
    'PLANT0050': {
        code: 'PLANT0050',
        msg: 'Plant extraction updated successfully'
    },
    'PLANT0051': {
        code: 'PLANT0051',
        msg: 'Invalid plant extraction id'
    },
    'PLANT0052': {
        code: 'PLANT0052',
        msg: 'Plant status updated successfully'
    },
    'PLANT0053': {
        code: 'PLANT0053',
        msg: 'Task should be created for this plant'
    },
    'PLANT0054': {
        code: 'PLANT0054',
        msg: 'Task already completed'
    },
    'PLANT0055': {
        code: 'PLANT0055',
        msg: 'Invalid plant functionality id'
    },
    'PLANT0056': {
        code: 'PLANT0056',
        msg: 'Plant reassigned successfully'
    },
    'PLANT0057': {
        code: 'PLANT0057',
        msg: 'Plant status is already reassigned'
    },
    'PLANT0058': {
        code: 'PLANT0058',
        msg: 'Plant status is already reassigned'
    },
    'PLANT0059': {
        code: 'PLANT0059',
        msg: 'Plant replacement suggestion list displayed successfully'
    },
    'PLANT0060': {
        code: 'PLANT0060',
        msg: 'Duplicate plant names displayed successfully'
    },
    'PLANT0061': {
        code: 'PLANT0061',
        msg: 'Plant marked as original successfully'
    },
    'PLANT0062': {
        code: 'PLANT0062',
        msg: 'Plant marked as duplicate successfully.'
    },
    'PLANT0063': {
        code: 'PLANT0063',
        msg: 'Plant lab samples displayed successfully.'
    },
    'PLANT0064': {
        code: 'PLANT0064',
        msg: 'Lab sample latest id fetched successfully.'
    },




    'LABSAMPLE0001': {
        code: 'LABSAMPLE0001',
        msg: 'Added Lab Sample successfully'
    },
    'LABSAMPLE0002': {
        code: 'LABSAMPLE0002',
        msg: 'Sample Lab Validation updated successfully'
    },

    'ADTIVE0001': {
        code: 'ADTIVE0001',
        msg: 'Additives saved successfully'
    },
    'ADTIVE0002': {
        code: 'ADTIVE0002',
        msg: 'Additives updated successfully'
    },
    'ADTIVE0003': {
        code: 'ADTIVE0003',
        msg: 'Additives properties display Successfully'
    },
    'ADTIVE0004': {
        code: 'ADTIVE0004',
        msg: 'additives list display successfully'
    },
    'ADTIVE0005': {
        code: 'ADTIVE0005',
        msg: 'Task saved successfully'
    },
    'ADTIVE0006': {
        code: 'ADTIVE0006',
        msg: 'Invalid status id'
    },
    'ADTIVE0007': {
        code: 'ADTIVE0007',
        msg: 'Invalid additive id'
    },
    'ADTIVE0008': {
        code: 'ADTIVE0008',
        msg: 'Additives task detail successfully'
    },
    'ADTIVE0009': {
        code: 'ADTIVE0009',
        msg: 'Additives task deleted successfully'
    },
    'ADTIVE0010': {
        code: 'ADTIVE0010',
        msg: 'Additives region saved successfully'
    },
    'ADTIVE0011': {
        code: 'ADTIVE0011',
        msg: 'Additives region list displayed successfully'
    },
    'ADTIVE0012': {
        code: 'ADTIVE0012',
        msg: 'Additives region detail displayed successfully'
    },
    'ADTIVE0013': {
        code: 'ADTIVE0013',
        msg: 'Additives functionalities saved successfully'
    },
    'ADTIVE0014': {
        code: 'ADTIVE0014',
        msg: 'Additives functionalities updated successfully'
    },
    'ADTIVE0015': {
        code: 'ADTIVE0015',
        msg: 'Additives functionalities list displayed successfully'
    },
    'ADTIVE0016': {
        code: 'ADTIVE0016',
        msg: 'Additives functionalities details displayed successfully'
    },
    'ADTIVE0017': {
        code: 'ADTIVE0017',
        msg: 'Additives functionalities deleted successfully'
    },
    'ADTIVE0018': {
        code: 'ADTIVE0018',
        msg: 'Additives physico detail displayed successfully'
    },
    'ADTIVE0019': {
        code: 'ADTIVE0019',
        msg: 'Additives organoleptic detail displayed successfully'
    },
    'ADTIVE0020': {
        code: 'ADTIVE0020',
        msg: 'Additives product categories saved successfully'
    },
    'ADTIVE0021': {
        code: 'ADTIVE0021',
        msg: 'Additives product categories displayed successfully'
    },
    'ADTIVE0022': {
        code: 'ADTIVE0022',
        msg: 'Additives product categories deleted successfully'
    },
    'ADTIVE0023': {
        code: 'ADTIVE0023',
        msg: 'Additives food categories saved successfully'
    },
    'ADTIVE0024': {
        code: 'ADTIVE0024',
        msg: 'Additives food categories displayed successfully'
    },
    'ADTIVE0025': {
        code: 'ADTIVE0025',
        msg: 'Additive food categories deleted successfully'
    },
    'ADTIVE0026': {
        code: 'ADTIVE0026',
        msg: 'Get additives count successfully'
    },
    'ADTIVE0027': {
        code: 'ADTIVE0027',
        msg: 'Additives status list displayed successfully'
    },
    'ADTIVE0028': {
        code: 'ADTIVE0028',
        msg: 'Additives replacement saved successfully'
    },
    'ADTIVE0029': {
        code: 'ADTIVE0029',
        msg: 'Additives replacement deleted successfully'
    },
    'ADTIVE0030': {
        code: 'ADTIVE0030',
        msg: 'Additives replacement region saved successfully'
    },
    'ADTIVE0031': {
        code: 'ADTIVE0031',
        msg: 'Invalid combination id.'
    },
    'ADTIVE0032': {
        code: 'ADTIVE0032',
        msg: 'Additives replacement region detail displayed successfully'
    },
    'ADTIVE0033': {
        code: 'ADTIVE0033',
        msg: 'Additives replacement region deleted successfully'
    },
    'ADTIVE0034': {
        code: 'ADTIVE0034',
        msg: 'Filters list displayed successfully'
    },
    'ADTIVE0035': {
        code: 'ADTIVE0035',
        msg: 'Additives synonym saved Successfully'
    },
    'ADTIVE0036': {
        code: 'ADTIVE0036',
        msg: 'Invalid language id Successfully'
    },
    'ADTIVE0037': {
        code: 'ADTIVE0037',
        msg: 'Additives synonym updated Successfully'
    },
    'ADTIVE0038': {
        code: 'ADTIVE0038',
        msg: 'Additives synonym deleted Successfully'
    },
    'ADTIVE0039': {
        code: 'ADTIVE0039',
        msg: 'Language list display Successfully'
    },
    'ADTIVE0040': {
        code: 'ADTIVE0040',
        msg: 'Additives synonyms List display Successfully'
    },
    'ADTIVE0041': {
        code: 'ADTIVE0041',
        msg: 'Task should be created for this additive'
    },
    'ADTIVE0042': {
        code: 'ADTIVE0042',
        msg: 'Task already completed'
    },
    'ADTIVE0043': {
        code: 'ADTIVE0043',
        msg: 'Additive Status Updated Successfully'
    },
    'ADTIVE0044': {
        code: 'ADTIVE0044',
        msg: 'Additive replacement updated Successfully'
    },
    'ADTIVE0045': {
        code: 'ADTIVE0045',
        msg: 'Additives replacement list display Successfully'
    },
    'ADTIVE0046': {
        code: 'ADTIVE0046',
        msg: 'Replacement already exist.'
    },
    'ADTIVE0047': {
        code: 'ADTIVE0047',
        msg: 'Additives synonym already exist.'
    },
    'ADTIVE0048': {
        code: 'ADTIVE0048',
        msg: 'Additive reassigned successfully.'
    },
    'ADTIVE0049': {
        code: 'ADTIVE0049',
        msg: 'Additive status is already reassigned.'
    },
    'ADTIVE0050': {
        code: 'ADTIVE0050',
        msg: 'Additive lookup list display Successfully'
    },
    'ADTIVE0051': {
        code: 'ADTIVE0051',
        msg: 'Plant replacement deleted Successfully'
    },
    'ADTIVE0052': {
        code: 'ADTIVE0052',
        msg: 'Error while deleting plant replacement'
    },
    'ADTIVE0053': {
        code: 'ADTIVE0053',
        msg: 'Group name not provided'
    },
    'ADTIVE0054': {
        code: 'ADTIVE0054',
        msg: 'Invalid additiveId id'
    },
    'ADTIVE0055': {
        code: 'ADTIVE0055',
        msg: 'Replacement Group name already exists'
    },
    'ADTIVE0056': {
        code: 'ADTIVE0056',
        msg: 'Error while creating replacement group'
    },
    'ADTIVE0057': {
        code: 'ADTIVE0057',
        msg: 'Please select additive plant replacement'
    },
    'ADTIVE0058': {
        code: 'ADTIVE0058',
        msg: 'Additive replacement group created successfully'
    },
    'ADTIVE0059': {
        code: 'ADTIVE0059',
        msg: 'Invalid additive id'
    },
    'ADTIVE0060': {
        code: 'ADTIVE0060',
        msg: 'Invalid additive replacement group'
    },
    'ADTIVE0061': {
        code: 'ADTIVE0061',
        msg: 'Invalid additive replacement group'
    },
    'ADTIVE0062': {
        code: 'ADTIVE0062',
        msg: 'Replacement group does not exists'
    },
    'ADTIVE0063': {
        code: 'ADTIVE0063',
        msg: 'Replacement group deleted successfully'
    },
    'ADTIVE0064': {
        code: 'ADTIVE0064',
        msg: 'Replacement Group name already exists'
    },
    'ADTIVE0065': {
        code: 'ADTIVE0065',
        msg: 'Error while updating additive replacement group'
    },
    'ADTIVE0066': {
        code: 'ADTIVE0066',
        msg: 'Additive replacement group updated successfully'
    },
    'ADTIVE0067': {
        code: 'ADTIVE0067',
        msg: 'Please select plant name.'
    },
    'ADTIVE0068': {
        code: 'ADTIVE0068',
        msg: 'Product category list displayed successfully.'
    },
    'ADTIVE0069': {
        code: 'ADTIVE0069',
        msg: 'Food category list displayed successfully.'
    },
    'ADTIVE0070': {
        code: 'ADTIVE0070',
        msg: 'Replacement log tags list display successfully.'
    },
    'ADTIVE0071': {
        code: 'ADTIVE0071',
        msg: 'Additives Replacement Details Fetched Successfully.'
    },
    'ADTIVE0072': {
        code: 'ADTIVE0072',
        msg: 'Invalid additive replacement group id.'
    },
    'ADTIVE0073': {
        code: 'ADTIVE0073',
        msg: 'Group log already created.'
    },
    'ADTIVE0074': {
        code: 'ADTIVE0074',
        msg: 'Additive replacement group log added successfully.'
    },
    'ADTIVE0075': {
        code: 'ADTIVE0075',
        msg: 'Unable to delete replacement group.'
    },
    'ADTIVE0076': {
        code: 'ADTIVE0076',
        msg: 'Additive replacement group approved successfully.'
    },
    'ADTIVE0077': {
        code: 'ADTIVE0077',
        msg: 'Invalid additive replacement log id'
    },
    'ADTIVE0078': {
        code: 'ADTIVE0078',
        msg: 'Additive replacement group log updated successfully.'
    },
    'ADTIVE0079': {
        code: 'ADTIVE0079',
        msg: 'Additive replacement group marked not approved.'
    },
    'ADTIVE0080': {
        code: 'ADTIVE0080',
        msg: 'Additive replacement tags fetched successfully.'
    },
    'ADTIVE0081': {
        code: 'ADTIVE0081',
        msg: 'Additive replacement tags updated successfully.'
    },
    'ADTIVE0082': {
        code: 'AADTIVE0082',
        msg: 'Error while updating additive replacement tags.'
    },
    'ADTIVE0083': {
        code: 'ADTIVE0083',
        msg: 'Additive replacement group property updated successfully.'
    },
    'ADTIVE0084': {
        code: 'ADTIVE0084',
        msg: 'Error while updating replacement group property.'
    },
    'ADTIVE0085': {
        code: 'ADTIVE0085',
        msg: "Additive Replacement used in group."
    },
    'ADTIVE0086': {
        code: 'ADTIVE0086',
        msg: "Replacement group property fetched successfully."
    },
    'ADTIVE0087': {
        code: 'ADTIVE0087',
        msg: "Property does not exists."
    },
    'ADTIVE0088': {
        code: 'ADTIVE0088',
        msg: 'Additive replacement group disaprpove successfully.'
    },
    'ADTIVE0089': {
        code: 'ADTIVE0089',
        msg: 'Task list displayed successfully.'
    },
    'ADTIVE0090': {
        code: 'ADTIVE0090',
        msg: 'Additive task assigned does not exists.'
    },
    'ADTIVE0091': {
        code: 'ADTIVE0091',
        msg: 'Status updated successfully.'
    },

    //
    'REGION0001': {
        code: 'REGION0001',
        msg: 'Invalid region id'
    },
    'REGION0002': {
        code: 'REGION0002',
        msg: 'Plants region saved successfully'
    },
    'REGION0003': {
        code: 'REGION0003',
        msg: 'Plants region list displayed successfully'
    },
    'REGION0004': {
        code: 'REGION0004',
        msg: 'Plants region details displayed successfully'
    },

    //   
    'PRODUCT0001': {
        code: 'PRODUCT0001',
        msg: 'User product saved successfully'
    },
    'PRODUCT0002': {
        code: 'PRODUCT0002',
        msg: 'Could not save product details'
    },
    'PRODUCT0003': {
        code: 'PRODUCT0003',
        msg: 'You already have product with this name, please choose different one'
    },
    'PRODUCT0004': {
        code: 'PRODUCT0004',
        msg: 'Invalid additive plant replacement id'
    },
    'PRODUCT0005': {
        code: 'PRODUCT0005',
        msg: 'Invalid product id and additive plant replacement id'
    },
    'PRODUCT0006': {
        code: 'PRODUCT0006',
        msg: 'Already created.'
    },
    'PRODUCT0007': {
        code: 'PRODUCT0007',
        msg: 'Product Not Found'
    },
    'PRODUCT0008': {
        code: 'PRODUCT0008',
        msg: 'Product images uploaded successfully'
    },
    'PRODUCT0009': {
        code: 'PRODUCT0009',
        msg: 'Action failed'
    },
    'PRODUCT0010': {
        code: 'PRODUCT0010',
        msg: 'Error occurred while uploading file'
    },
    'PRODUCT0011': {
        code: 'PRODUCT0011',
        msg: 'Product categories list displayed successfully'
    },
    'PRODUCT0012': {
        code: 'PRODUCT0012',
        msg: 'Product list displayed successfully'
    },
    'PRODUCT0013': {
        code: 'PRODUCT0013',
        msg: 'Product image deleted successfully'
    },
    'PRODUCT0014': {
        code: 'PRODUCT0014',
        msg: 'Error occurred while deleting product image'
    },
    'PRODUCT0015': {
        code: 'PRODUCT0015',
        msg: 'Product deleted successfully'
    },
    'PRODUCT0016': {
        code: 'PRODUCT0016',
        msg: 'Upload at least 1 file'
    },
    'PRODUCT0017': {
        code: 'PRODUCT0017',
        msg: 'Maximum files limit reached'
    },
    'PRODUCT0018': {
        code: 'PRODUCT0018',
        msg: 'Product updated successfully'
    },
    'PRODUCT0019': {
        code: 'PRODUCT0019',
        msg: ' Product image deleted successfully'
    },
    'PRODUCT0020': {
        code: 'PRODUCT0020',
        msg: 'Product details fetched successfully'
    },
    'PRODUCT0021': {
        code: 'PRODUCT0021',
        msg: 'Product ingredients list displayed successfully'
    },
    'PRODUCT0022': {
        code: 'PRODUCT0022',
        msg: 'Product ingredient updated successfully'
    },
    'PRODUCT0023': {
        code: 'PRODUCT0023',
        msg: 'Product ingredient deleted successfully'
    },
    'PRODUCT0024': {
        code: 'PRODUCT0024',
        msg: 'Product default image updated successfully'
    },
    'PRODUCT0025': {
        code: 'PRODUCT0025',
        msg: 'Product status updated successfully'
    },
    'PRODUCT0026': {
        code: 'PRODUCT0026',
        msg: 'Invalid product category id'
    },
    'PRODUCT0027': {
        code: 'PRODUCT0027',
        msg: 'Product shared successfully'
    },
    'PRODUCT0028': {
        code: 'PRODUCT0028',
        msg: 'Shared products list displayed successfully'
    },
    'PRODUCT0029': {
        code: 'PRODUCT0029',
        msg: 'Product already shared with Emails list displayed successfully'
    },
    'PRODUCT0030': {
        code: 'PRODUCT0030',
        msg: 'Email revoked successfully'
    },
    'PRODUCT0031': {
        code: 'PRODUCT0031',
        msg: 'Popular products list displayed successfully'
    },
    'PRODUCT0032': {
        code: 'PRODUCT0032',
        msg: 'Product replacements searched Successfully.'
    },
    'PRODUCT0033': {
        code: 'PRODUCT0033',
        msg: 'Product Additive replacement added successfully'
    },
    'PRODUCT0034': {
        code: 'PRODUCT0034',
        msg: 'Product additive replacement deleted successfully'
    },
    'PRODUCT0035': {
        code: 'PRODUCT0035',
        msg: 'Invalid product replacement log id'
    },
    'PRODUCT0036': {
        code: 'PRODUCT0036',
        msg: 'Product replacement log added successfully'
    },
    'PRODUCT0037': {
        code: 'PRODUCT0037',
        msg: 'Invalid product additive replacement id.'
    },
    'PRODUCT0038': {
        code: 'PRODUCT0038',
        msg: 'Product Additive Not Found.'
    },
    'PRODUCT0039': {
        code: 'PRODUCT0039',
        msg: 'Product replacement log details fetched successfully.'
    },
    'PRODUCT0040': {
        code: 'PRODUCT0040',
        msg: 'Product replacement log updated successfully'
    },
    'PRODUCT0041': {
        code: 'PRODUCT0041',
        msg: 'Product replacement details fetched successfully'
    },
    'PRODUCT0042': {
        code: 'PRODUCT00042',
        msg: 'User comment saved successfully'
    },
    'PRODUCT0043': {
        code: 'PRODUCT0043',
        msg: 'new comment is same as previous comment'
    },
    'PRODUCT0044': {
        code: 'PRODUCT0044',
        msg: 'Replacement log tags list display successfully.'
    },
    'PRODUCT0045': {
        code: 'PRODUCT0045',
        msg: 'Product replacement created successfully.'
    },
    'PRODUCT0046': {
        code: 'PRODUCT0046',
        msg: 'Replacement Group name already exists.'
    },
    'PRODUCT0047': {
        code: 'PRODUCT0047',
        msg: 'Error while creating replacement group.'
    },
    'PRODUCT0048': {
        code: 'PRODUCT0048',
        msg: 'Combination already exists.'
    },
    'PRODUCT0049': {
        code: 'PRODUCT0049',
        msg: 'Group name not provided.'
    },
    'PRODUCT0050': {
        code: 'PRODUCT0050',
        msg: 'Please select plant name.'
    },
    'PRODUCT0051': {
        code: 'PRODUCT0051',
        msg: 'Additive plant replacement updated successfully.'
    },
    'PRODUCT0052': {
        code: 'PRODUCT0052',
        msg: 'Error while updating additive plant replacement.'
    },
    'PRODUCT0053': {
        code: 'PRODUCT0053',
        msg: 'Replacement group does not exists.'
    },
    'PRODUCT0054': {
        code: 'PRODUCT0054',
        msg: 'Group deleted successfully.'
    },
    'PRODUCT0055': {
        code: 'PRODUCT0055',
        msg: 'Error occured while deleting plant additive replacement.'
    },
    'PRODUCT0056': {
        code: 'PRODUCT0056',
        msg: 'No product replacement found.'
    },
    'PRODUCT0057': {
        code: 'PRODUCT0057',
        msg: 'Replacement group log detail fetced successfully.'
    },
    'PRODUCT0058': {
        code: 'PRODUCT0058',
        msg: 'Product Replacement group Log Updated Successfully.'
    },
    'PRODUCT0059': {
        code: 'PRODUCT0059',
        msg: 'Invalid product replacement group id.'
    },
    'PRODUCT0060': {
        code: 'PRODUCT0060',
        msg: 'Invalid product replacement group log id.'
    },
    'PRODUCT0061': {
        code: 'PRODUCT0061',
        msg: 'Product replacement group log added successfully.'
    },
    'PRODUCT0062': {
        code: 'PRODUCT0062',
        msg: 'Invalid product replacement group id.'
    },
    'PRODUCT0063': {
        code: 'PRODUCT0063',
        msg: 'Formulation name already exists.'
    },
    'PRODUCT0064': {
        code: 'PRODUCT0064',
        msg: 'Error while creating formulation group.'
    },
    'PRODUCT0065': {
        code: 'PRODUCT0065',
        msg: 'Please select replacement group name.'
    },
    'PRODUCT0066': {
        code: 'PRODUCT0066',
        msg: 'Product formulation created successfully.'
    },
    'PRODUCT0067': {
        code: 'PRODUCT0067',
        msg: 'Error while updating product formulation.'
    },
    'PRODUCT0068': {
        code: 'PRODUCT0068',
        msg: 'Product formulation updated successfully.'
    },
    'PRODUCT0069': {
        code: 'PRODUCT0069',
        msg: 'Invalid formulation id.'
    },
    'PRODUCT0070': {
        code: 'PRODUCT0070',
        msg: 'Unable to delete formulation at moment.'
    },
    'PRODUCT0071': {
        code: 'PRODUCT0071',
        msg: 'Product formulation fetched successfully.'
    },
    'PRODUCT0072': {
        code: 'PRODUCT0072',
        msg: 'Formulation name not provided.'
    },
    'PRODUCT0077': {
        code: 'PRODUCT0077',
        msg: 'Please select something before submit.'
    },
    'PRODUCT0078': {
        code: 'PRODUCT0078',
        msg: 'Product formulation does not exists.'
    },
    'PRODUCT0079': {
        code: 'PRODUCT0079',
        msg: 'Product formulation log detail fetced successfully.'
    },
    'PRODUCT0080': {
        code: 'PRODUCT0080',
        msg: 'Product formulation log added successfully.'
    },
    'PRODUCT0081': {
        code: 'PRODUCT0081',
        msg: 'Invalid formulation log id.'
    },
    'PRODUCT0082': {
        code: 'PRODUCT0082',
        msg: 'Product formulation log updated successfully.'
    },
    'PRODUCT0083': {
        code: 'PRODUCT0083',
        msg: 'Replacement group log tags list display successfully.'
    },
    'PRODUCT0084': {
        code: 'PRODUCT0084',
        msg: 'Formulation log tags list display successfully.'
    },
    'PRODUCT0085': {
        code: 'PRODUCT0085',
        msg: 'Formulation deleted successfully.'
    },
    'PRODUCT0086': {
        code: 'PRODUCT0086',
        msg: 'Plant marked as duplicate successfully.'
    },
    'PRODUCT0087': {
        code: 'PRODUCT0087',
        msg: 'Product additive feedback added successfully.'
    },
    'PRODUCT0088': {
        code: 'PRODUCT0088',
        msg: 'Group log not provided.'
    },
    'PRODUCT0089': {
        code: 'PRODUCT0089',
        msg: 'Product replacement group duplicate created successfully.'
    },
    'PRODUCT0090': {
        code: 'PRODUCT0090',
        msg: 'Product replacement formulation duplicate created successfully.'
    },
    'PRODUCT0091': {
        code: 'PRODUCT0091',
        msg: 'Could not create Product replacement group duplicate'
    },
    'PRODUCT0092': {
        code: 'PRODUCT0092',
        msg: 'Could not create Product replacement formulation duplicate'
    },
    'PRODUCT0093': {
        code: 'PRODUCT0093',
        msg: 'Products team members roles list Successfully'
    },
    'PRODUCT0094': {
        code: 'PRODUCT0094',
        msg: 'Products team members list Successfully'
    },
    'PRODUCT0095': {
        code: 'PRODUCT0095',
        msg: 'Products team members added Successfully'
    },
    'PRODUCT0096': {
        code: 'PRODUCT0096',
        msg: 'Products team members edited Successfully'
    },
    'PRODUCT0097': {
        code: 'PRODUCT0097',
        msg: 'Products team member deleted Successfully'
    },
    'PRODUCT0098': {
        code: 'PRODUCT0098',
        msg: 'Products team member not found'
    },
    'PRODUCT0099': {
        code: 'PRODUCT0099',
        msg: 'Products team members deleted Successfully'
    },
    'PRODUCT0100': {
        code: 'PRODUCT00100',
        msg: 'Member doesnt exists'
    },
    'PRODUCT0101': {
        code: 'PRODUCT00101',
        msg: 'KPI Listing list Successfully'
    },

    'PRODUCT0102': {
        code: 'PRODUCT00101',
        msg: 'Create SensoryEvaluation Successfully '
    },
    'PRODUCT00400': {
        code: 'PRODUCT00400',
        msg: 'Invalid to SensoryEvaluation'
    },
    'PRODUCT00103': {
        code: 'PRODUCT00103',
        msg: 'get sensory evaluation Successfully'
    },
    'PRODUCT0104': {
        code: 'PRODUCT00104',
        msg: 'product doesnt exists'
    },
    'PRODUCT0105': {
        code: 'PRODUCT00100',
        msg: 'Sensory Evaluation does not exists'
    },
    'PRODUCT00106': {
        code: 'PRODUCT00106',
        msg: 'Sensory Eavluation edited Successfully'
    },
    'PRODUCT00107': {
        code: 'PRODUCT00107',
        msg: 'Sensory Evaluation deleted Successfully'
    },
    'PRODUCT0108': {
        code: 'PRODUCT00108',
        msg: 'Sensory Evaluation doesnt exists'
    },
    'PRODUCT00109': {
        code: 'PRODUCT00109',
        msg: 'Formulation trial deleted Successfully'
    },
    'PRODUCT00110': {
        code: 'PRODUCT00110',
        msg: 'kpi deleted Successfully'
    },
    'PRODUCT00111': {
        code: 'PRODUCT00111',
        msg: 'Kpi doesnt exists'
    },
    'PRODUCT00112': {
        code: 'PRODUCT0011',
        msg: 'Product doesnt edit'
    },
    'PRODUCT00113': {
        code: 'PRODUCT00113',
        msg: 'Something went wrong while adding Feedback'
    },
    'PRODUCT00114': {
        code: 'PRODUCT00114',
        msg: 'Not authorised to change status of this formulation'
    },
    'PRODUCT00115': {
        code: 'PRODUCT00115',
        msg: 'Product formulation workflow status updated successfully.'
    },
    'PRODUCT00116': {
        code: 'PRODUCT00116',
        msg: 'Formulation workflow log fetched successfully.'
    },
    'PRODUCT00117': {
        code: 'PRODUCT00117',
        msg: 'Formulation workflow status log has not been updated'
    },
    // for chat response code
    'CHAT0001': {
        code: 'CHAT0001',
        msg: 'User list displayed succesfully.'
    },
    'CHAT0002': {
        code: 'CHAT0002',
        msg: `Server error, please try again later!`
    },
    'CHAT0003': {
        code: 'CHAT0003',
        msg: `Message saved successfully`
    },
    'CHAT0004': {
        code: 'CHAT0004',
        msg: `Message successfully loaded`
    },
    'CHAT0005': {
        code: 'CHAT0005',
        msg: `Unable to fetch messages`
    },
    'CHAT0006': {
        code: 'CHAT0006',
        msg: `Chat room list displayed successfully`
    },
    'CHAT0007': {
        code: 'CHAT0007',
        msg: `User status updated successfully`
    },
    'CHAT0008': {
        code: 'CHAT0008',
        msg: `Invalid chat room`
    },
    'CHAT0009': {
        code: 'CHAT0009',
        msg: `Unable to change unread count for user.`
    },
    'CHAT0010': {
        code: 'CHAT0010',
        msg: `Unread count changed for the user.`
    },
    'CHAT0011': {
        code: 'CHAT0011',
        msg: `All user displayed successfully.`
    },
    'CHAT0012': {
        code: 'CHAT0012',
        msg: `Unable to fetch users.`
    },
    'CHAT0013': {
        code: 'CHAT0013',
        msg: `Group created successfully.`
    },
    'CHAT0014': {
        code: 'CHAT0014',
        msg: `User added to group successfully.`
    },
    'CHAT0015': {
        code: 'CHAT0015',
        msg: `Unable to add users to group.`
    },
    'CHAT0016': {
        code: 'CHAT0016',
        msg: `Error occured while creating chat room.`
    },
    'CHAT0017': {
        code: 'CHAT0017',
        msg: `Please select user to remove.`
    },
    'CHAT0018': {
        code: 'CHAT0018',
        msg: `Failed to remove user.`
    },
    'CHAT0019': {
        code: 'CHAT0019',
        msg: `User removed.`
    },
    'CHAT0020': {
        code: 'CHAT0020',
        msg: `Unable to change group name.`
    },
    'CHAT0021': {
        code: 'CHAT0021',
        msg: `Group name changed successfully.`
    },
    'CHAT0022': {
        code: 'CHAT0022',
        msg: `Group creator name displayed successfully.`
    },
    'CHAT0023': {
        code: 'CHAT0023',
        msg: `Error while updating group image.`
    },
    'CHAT024': {
        code: 'CHAT024',
        msg: `Group image chnaged successfully.`
    },
    'CHAT025': {
        code: 'CHAT025',
        msg: `Please select a image to upload.`
    },
     
     //support response codes
    'SUPPORT0001': {
        code: 'SUPPORT0001',
        msg: `Tickets list displayed successfully`
    },
    'SUPPORT0002': {
        code: 'SUPPORT0002',
        msg: 'Tickets has been raised successfully'
    },
    'SUPPORT0003': {
        code: 'SUPPORT0003',
        msg: 'Failed to raise Ticket'
    },
    'SUPPORT0004': {
        code: 'SUPPORT0004',
        msg: 'Document has been uploaded successfully'
    },
    'SUPPORT0005': {
        code: 'SUPPORT0005',
        msg: 'Failed to upload document'
    },
    'SUPPORT0006': {
        code: 'SUPPORT0006',
        msg: 'Email has been sent successfully'
    },
    'SUPPORT0007': {
        code: 'SUPPORT0007',
        msg: 'Failed to send Email'
    },
    'SUPPORT0008': {
        code: 'SUPPORT0008',
        msg: 'Ticket Not Found'
    },
    'SUPPORT0009': {
        code: 'SUPPORT0009',
        msg: 'User comment saved successfully'
    },
    'SUPPORT0010': {
        code: 'SUPPORT0010',
        msg: 'Failed to save comment'
    },
    'SUPPORT0011': {
        code: 'SUPPORT0011',
        msg: 'Ticket status updated successfully'
    },
    'SUPPORT0012': {
        code: 'SUPPORT0012',
        msg: 'Ticket detail fetched successfully'
    },




    'PROJECT0001' : {
        code: 'PROJECT0001',
        msg: 'Project setting fetched successfully'
    },
    'PROJECT0002' : {
        code: 'PROJECT0002',
        msg: 'Unable to load project setting'
    }
    
}

// add below code for maintain response message formatting
let unFormatSet = ["AUTH0017"]


for (let index in responseCode) {
    if (!unFormatSet.includes(index))
        responseCode[index].msg = utility.titleCase(responseCode[index].msg);
}

export default responseCode;

