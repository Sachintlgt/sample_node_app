declare global {
    namespace NodeJS {
        interface Global {
            path:string
        }
    }
}
export default global;