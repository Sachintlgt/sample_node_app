
let Options ={
    swaggerDefinition: {
        info: {
            title: `${process.env.APP_NAME} API`,
            version:'',
            description: `${process.env.APP_NAME} API Information`,
            contact: {
                name: `Rupesh Rajhans`
            },
            host: [`${process.env.APP_URL}:${process.env.APP_PORT}`]
        },
        basePath:`/api/${process.env.APP_VERSION}`

    },
    apis: ['**/*.ts']
}

export default Options;