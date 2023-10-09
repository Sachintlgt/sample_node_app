
interface Registration{
    firstName: string,
    lastName?: string,
    email: string,
    password: string,
    status: number,
    createdBy: string| any,
    createdAt: string
}

interface CreateUser{
    firstName: string,
    lastName?: string,
    email: string,
    address?: string,
    phone?: number,
    avatar?: string,
    roleIds?: any,
    companyId? : string,
    productCategories? : string
    status: number,
    createdBy: string| any
}

interface Login{
    email: string,
    password: string,
}

interface UserMapWithRole{
    userId: number |any,
    roleId: number
}

interface UpdatePassword{
    userId: number|any,
    password: string
}

interface UpdateProfile{
    userId: number|any,
    firstName?: string | unknown,
    lastName?: string | unknown,
    companyId?: string | unknown,
    productCategories?: string | unknown,
    countryCode?: number | unknown,
    phone?: number | unknown,
    avatar?: string | unknown,
    address?: string | unknown,
    status?: number | unknown,
    roles?: any,
    email?: string,
    updatedBy:any,
    updatedAt?: string | unknown

}

interface updateUserStatus{
    userId: number,
    statusId: number,
}

export {Registration, Login, UserMapWithRole, UpdatePassword,UpdateProfile, CreateUser,updateUserStatus};