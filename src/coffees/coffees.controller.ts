import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';

import { ActiveUser } from '../iam/decorators/active-user.decorator';
import { Roles } from '../iam/authorization/decorators/roles.decorator';
import { Permissions } from '../iam/authorization/decorators/permissions.decorator';
import { Policies } from '../iam/authorization/decorators/policies.decorator';

import { ActiveUserData } from '../iam/interfaces/active-user-data.interface';

import { Role } from '../users/enums/role.enum';

import { Permission } from '../iam/authorization/permission.type';

import { FrameworkContributorPolicy } from '../iam/authorization/policies/framework-contributor.policy';

import { CoffeesService } from './coffees.service';

import { CreateCoffeeDto } from './dto/create-coffee.dto';
import { UpdateCoffeeDto } from './dto/update-coffee.dto';

@Controller('coffees')
export class CoffeesController {
  constructor(private readonly coffeesService: CoffeesService) {}

  // @Roles(Role.Admin)
  // @Permissions(Permission.CreateCoffee)
  @Policies(
    new FrameworkContributorPolicy() /** new MinAgePolicy(18), new OnlyAdminPolicy() */,
  )
  @Post()
  create(@Body() createCoffeeDto: CreateCoffeeDto) {
    return this.coffeesService.create(createCoffeeDto);
  }

  @Get()
  findAll(@ActiveUser() user: ActiveUserData) {
    console.log(user);
    return this.coffeesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.coffeesService.findOne(+id);
  }

  @Roles(Role.Admin)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateCoffeeDto: UpdateCoffeeDto) {
    return this.coffeesService.update(+id, updateCoffeeDto);
  }

  @Roles(Role.Admin)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.coffeesService.remove(+id);
  }
}
